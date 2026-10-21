"""Synthetic rejection/round-trip tests. No Apple, GitHub, source or real signing input."""
import base64,contextlib,copy,hashlib,io,json,os,shutil,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import sealed_payload as crypto
import source_snapshot as snap
import context_adapter as adapter
import prepare_payload as prep
import run_sealed_ios as controller
import sealed_ios_context as binding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SENTINEL='SYNTHETIC_PRIVATE_SENTINEL_MUST_NOT_REACH_PUBLIC_OUTPUT'
# A Windows venv launcher can exit while its separate Store Python remains.
# Test the actual interpreter process; production is POSIX and owns its PGID.
TEST_PYTHON=str(Path(sys.base_prefix)/'python.exe') if os.name=='nt' else sys.executable
def fake_builder(role='driver',fail=False):
 return ('''import os,json,shutil,tempfile
from pathlib import Path
ROLE='''+repr(role)+'''
EXPECTED_REPOSITORY='synthetic/private'
import re
def require(value,code):
 if not value:raise ValueError(code)
def validate_inputs(environment):
'''+adapter.OLD+'''
    require(environment.get('RIDES_IOS_UPLOAD')=='false','synthetic_no_upload')
def unchanged_guard(value):
 require(value is True,'synthetic_guard')
def cleanup_owned_inputs(private,*args,**kwargs):
 shutil.rmtree(private)
def build(environment):
 validate_inputs(environment)
 root=Path(__file__).resolve().parents[1]
 private=Path(tempfile.mkdtemp(prefix='rouhi-testflight-',dir=environment['RUNNER_TEMP']))
 (private/'tools.log').write_text('''+repr(SENTINEL)+''')
 try:
  print('''+repr(SENTINEL)+''')
'''+("  raise ValueError('synthetic_native_failure')\n" if fail else "  unchanged_guard(True)\n")+'''
 finally:cleanup_owned_inputs(private)
 out=root/'build/testflight-output';out.mkdir(parents=True)
 (out/'synthetic.ipa').write_bytes(b'synthetic-ipa-only')
 (out/'Podfile.lock').write_text('synthetic-lock-only')
 (out/'receipt.json').write_text(json.dumps({'private_signing_cleanup_verified':True,'apple_binary_validation_succeeded':True,'upload_command_succeeded':False,'public_submission_performed':False,'source_sha':environment['RIDES_IOS_SOURCE_SHA']}))
''').encode()
def gh():
 e=dict(os.environ);e.update(GITHUB_REPOSITORY=controller.REPO,GITHUB_REPOSITORY_OWNER='mahdiii2',GITHUB_ACTOR='mahdiii2',GITHUB_TRIGGERING_ACTOR='mahdiii2',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/main',GITHUB_SHA='a'*40,GITHUB_RUN_ID='12345',GITHUB_RUN_ATTEMPT='1',REVIEWED_HELPER_SHA='a'*40,RUNNER_ENVIRONMENT='github-hosted');return e
def secret(role='driver'):
 e={k:'synthetic-only' for k in snap.PRIVATE_KEYS};e.update(ASC_APP_ID={'driver':'6821815632','customer':'6821814203'}[role],RIDES_IOS_BUILD_NUMBER='7',RIDES_IOS_VERSION='1.0');return e
def rows_for(root):
 return sorted([{'path':p.relative_to(root).as_posix(),'size':p.stat().st_size,'sha256':crypto.digest_file(p),'mode':0o755 if p.name=='gradlew' else 0o644} for p in root.rglob('*') if p.is_file()],key=lambda x:x['path'])
class SyntheticSecurity:
 """Models command state, not Apple cryptography; never touches real keychains."""
 def __init__(self,root,private_home,shared=False):
  self.real_run=subprocess.run;self.home=str(private_home);self.calls=[];self.fail=None;self.ignore=None;self.shared=shared
  login=root/'original-login.keychain-db';login.write_bytes(b'KEEP-ORIGINAL-PUBLIC-SYNTHETIC')
  self.normal={'default':str(login),'search':[str(login)]};self.child=self.normal if shared else {'default':None,'search':[]}
 def state(self,env):return self.child if env.get('HOME')==self.home else self.normal
 def __call__(self,args,**kw):
  if args[0]!='/usr/bin/security':return self.real_run(args,**kw)
  self.calls.append(args.copy());env=kw['env'];state=self.state(env);verb=args[1]
  if self.fail is not None and self.fail(args,env):return subprocess.CompletedProcess(args,1,b'',b'synthetic-security-failure')
  if verb in {'list-keychains','default-keychain'}:
   key='search' if verb=='list-keychains' else 'default'
   if '-s' in args:
    values=args[args.index('-s')+1:]
    # SecKeychainSetDomainDefault calls Keychain::optional(NULL): current default,
    # not absence. Reproduce that Apple behavior rather than inventing an unset.
    if key=='default' and not values:
     return subprocess.CompletedProcess(args,0 if state[key] is not None else 1,b'',b'')
    if self.ignore is None or not self.ignore(args,env):state[key]=values if key=='search' else values[0]
    out=b''
   else:
    values=state[key] if key=='search' else ([] if state[key] is None else [state[key]])
    out=('    <NULL>\n' if key=='default' and state[key] is None else ''.join('    "'+x+'"\n' for x in values)).encode()
  elif verb=='create-keychain':
   target=Path(args[-1]);target.write_bytes(b'SYNTHETIC-PUBLIC-CMS-CERTS-ONLY');state['search'].append(str(target))
   if state['default'] is None:state['default']=str(target)
   out=b''
  elif verb=='unlock-keychain':out=b''
  elif verb=='delete-keychain':
   target=Path(args[-1]);target.unlink()
   for context in [self.child,self.normal]:
    context['search']=[x for x in context['search'] if x!=str(target)]
    if context['default']==str(target):context['default']=None
   out=b''
  else:raise AssertionError('Unlisted synthetic Security command')
  return subprocess.CompletedProcess(args,0,out,b'')

class SealedBoundaryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
  cls.private=cls.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
  cls.public=cls.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);cls.pubsha=hashlib.sha256(cls.public).hexdigest();cls.git=shutil.which('git')
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.addCleanup(self.temp.cleanup)
 def path(self,name):return self.root/name
 def fixture(self,role='driver',fail=False):
  source=self.path('source-'+role);(source/'tools').mkdir(parents=True);raw=fake_builder(role,fail);(source/'tools/build_testflight.py').write_bytes(raw);(source/'gradlew').write_bytes(b'synthetic-only');(source/'plain.txt').write_bytes(b'synthetic-source')
  output=self.path('sealed-'+role);key=os.urandom(32)
  with patch.dict(adapter.BASELINES,{role:hashlib.sha256(raw).hexdigest()}):r=prep.prepare(source,rows_for(source),role,secret(role),output,key,self.git)
  return output,key,r,raw
 def test_streaming_input_roundtrip_and_authentication(self):
  src=self.path('plain');src.write_bytes(os.urandom(3*1024**2+31));key=os.urandom(32);ctx={'role':'driver','source_sha':'b'*40,'manifest_sha256':'c'*64}
  sealed=self.path('in.sealed');crypto.seal_input(src,sealed,key,ctx,4*1024**2);out=self.path('out');crypto.open_payload(sealed,out,key=key,context=ctx,maximum=4*1024**2);self.assertEqual(src.read_bytes(),out.read_bytes())
 def test_wrong_input_key_leaves_no_unauthenticated_plaintext(self):
  src=self.path('p');src.write_bytes(SENTINEL.encode());sealed=self.path('c');crypto.seal_input(src,sealed,os.urandom(32),{'x':1},1000);out=self.path('o')
  with self.assertRaises(Exception):crypto.open_payload(sealed,out,key=os.urandom(32),context={'x':1},maximum=1000)
  self.assertFalse(out.exists())
 def test_encrypt_preexisting_destination_is_never_removed(self):
  src=self.path('p');src.write_bytes(b'synthetic');dst=self.path('valuable');dst.write_bytes(b'KEEP-EXISTING')
  with self.assertRaises(FileExistsError):crypto.seal_input(src,dst,os.urandom(32),{},1000)
  self.assertEqual(dst.read_bytes(),b'KEEP-EXISTING')
 def test_decrypt_preexisting_destination_survives_valid_and_invalid_envelopes(self):
  src=self.path('p');src.write_bytes(b'synthetic');sealed=self.path('c');key=os.urandom(32);crypto.seal_input(src,sealed,key,{},1000);dst=self.path('valuable');dst.write_bytes(b'KEEP-EXISTING')
  with self.assertRaises(FileExistsError):crypto.open_payload(sealed,dst,key=key,context={},maximum=1000)
  self.assertEqual(dst.read_bytes(),b'KEEP-EXISTING');sealed.write_bytes(b'invalid')
  with self.assertRaises(Exception):crypto.open_payload(sealed,dst,key=key,context={},maximum=1000)
  self.assertEqual(dst.read_bytes(),b'KEEP-EXISTING')
 def test_ciphertext_tampering_leaves_no_plaintext(self):
  src=self.path('p');src.write_bytes(b'x'*1000);sealed=self.path('c');key=os.urandom(32);crypto.seal_input(src,sealed,key,{'x':1},2000);raw=bytearray(sealed.read_bytes());raw[-17]^=1;sealed.write_bytes(raw);out=self.path('o')
  with self.assertRaises(Exception):crypto.open_payload(sealed,out,key=key,context={'x':1},maximum=2000)
  self.assertFalse(out.exists())
 def test_context_mismatch_rejected_before_plaintext(self):
  src=self.path('p');src.write_bytes(b'x');sealed=self.path('c');key=os.urandom(32);crypto.seal_input(src,sealed,key,{'role':'driver'},1000)
  with self.assertRaises(Exception):crypto.open_payload(sealed,self.path('o'),key=key,context={'role':'customer'},maximum=1000)
  self.assertFalse(self.path('o').exists())
 def test_owner_encrypted_output_large_roundtrip(self):
  src=self.path('p');src.write_bytes(os.urandom(2*1024**2+11));sealed=self.path('c');ctx={'kind':'synthetic-output'};crypto.seal_output(src,sealed,self.public,self.pubsha,ctx,3*1024**2);crypto.open_payload(sealed,self.path('o'),private_pem=self.private,context=ctx,maximum=3*1024**2);self.assertEqual(crypto.digest_file(src),crypto.digest_file(self.path('o')))
 def test_changed_public_key_pin_rejected(self):
  src=self.path('p');src.write_bytes(b'x')
  with self.assertRaises(ValueError):crypto.seal_output(src,self.path('o'),self.public,'0'*64,{},1000)
  self.assertFalse(self.path('o').exists())
 def test_wrong_owner_private_key_rejected(self):
  src=self.path('p');src.write_bytes(b'x');sealed=self.path('c');crypto.seal_output(src,sealed,self.public,self.pubsha,{},1000);wrong=rsa.generate_private_key(public_exponent=65537,key_size=3072).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
  with self.assertRaises(Exception):crypto.open_payload(sealed,self.path('o'),private_pem=wrong,context={},maximum=1000)
  self.assertFalse(self.path('o').exists())
 def test_duplicate_json_fields_rejected(self):
  with self.assertRaises(ValueError):crypto.json_bytes(b'{"a":1,"a":2}')
 def test_member_count_and_path_aliases(self):
  for value in ['../x','/x','a/../b','C:/x','a\\b','.git/config','a/.GIT/config','x\nname','a.','e\u0301']:
   with self.subTest(value=value),self.assertRaises(ValueError):snap.path_name(value)
  row={'path':'A','size':1,'sha256':'a'*64,'mode':0o644}
  with self.assertRaises(ValueError):snap.validate_rows([row,row|{'path':'a'}])
 def malformed_tar(self,member):
  p=self.path('bad.tar')
  with tarfile.open(p,'w',format=tarfile.USTAR_FORMAT) as t:t.addfile(member,io.BytesIO(b'x') if member.isfile() else None)
  out=self.path('unpacked');out.mkdir()
  with self.assertRaises(ValueError):snap.extract_payload(p,out,{},'0'*64)
  self.assertEqual(list(out.iterdir()),[])
 def test_tar_traversal_no_escape(self):
  m=tarfile.TarInfo('../escape');m.size=1;m.mode=0o644;self.malformed_tar(m);self.assertFalse(self.path('escape').exists())
 def test_tar_symlink_rejected_before_extraction(self):
  m=tarfile.TarInfo('source/link');m.type=tarfile.SYMTYPE;m.linkname='/tmp/elsewhere';m.mode=0o644;self.malformed_tar(m)
 def test_tar_hardlink_rejected_before_extraction(self):
  m=tarfile.TarInfo('source/link');m.type=tarfile.LNKTYPE;m.linkname='source/a';m.mode=0o644;self.malformed_tar(m)
 def test_tar_device_rejected_before_extraction(self):
  m=tarfile.TarInfo('source/device');m.type=tarfile.CHRTYPE;m.mode=0o644;self.malformed_tar(m)
 def test_adapter_preserves_every_non_context_byte(self):
  raw=fake_builder();sha=hashlib.sha256(raw).hexdigest()
  with patch.dict(adapter.BASELINES,{'driver':sha}):after=adapter.adapt(raw,'driver')
  self.assertEqual(after.decode().replace(adapter.NEW,adapter.OLD,1).encode(),raw)
 def test_adapter_rejects_stale_predecessor(self):
  with self.assertRaises(ValueError):adapter.adapt(fake_builder(),'driver')
 def test_generated_snapshot_reproducible_and_owning_git_untouched(self):
  source=self.path('s');source.mkdir();(source/'a.txt').write_bytes(b'A');rows=rows_for(source);one=self.path('one');two=self.path('two');shutil.copytree(source,one);shutil.copytree(source,two);h=self.path('h');h.mkdir()
  a=snap.git_snapshot(one,rows,self.git,h);b=snap.git_snapshot(two,rows,self.git,h);self.assertEqual(a,b);self.assertFalse((source/'.git').exists())
 def test_source_hash_changed_rejected(self):
  root=self.path('s');root.mkdir();(root/'a').write_bytes(b'A');rows=rows_for(root);(root/'a').write_bytes(b'B')
  with self.assertRaises(ValueError):snap.verify_source(root,rows)
 def test_unlisted_source_file_rejected(self):
  root=self.path('s');root.mkdir();(root/'a').write_bytes(b'A');rows=rows_for(root);(root/'unexpected').write_bytes(b'B')
  with self.assertRaises(ValueError):snap.verify_source(root,rows)
 def test_preparer_refuses_output_inside_owning_source(self):
  source=self.path('s');source.mkdir()
  with self.assertRaises(ValueError):prep.prepare(source,[],'driver',secret(),source/'bad',os.urandom(32),self.git)
 def test_exact_archive_fixture_extracts_and_source_commit_matches(self):
  output,key,r,raw=self.fixture();archive=self.path('decrypted.tar');ctx={k:r[k] for k in ['role','source_sha','manifest_sha256']};crypto.open_payload(output/'input.sealed',archive,key=key,context=ctx,maximum=controller.MAX_INPUT);dest=self.path('unpacked');dest.mkdir()
  with patch.dict(adapter.BASELINES,{'driver':hashlib.sha256(raw).hexdigest()}):m,e=snap.extract_payload(archive,dest,ctx,r['manifest_sha256'])
  home=self.path('home');home.mkdir();self.assertEqual(snap.git_snapshot(dest/'source',m['files'],self.git,home),r['source_sha']);self.assertEqual(set(e),snap.PRIVATE_KEYS)
 def test_reserved_private_environment_cannot_inject_github_or_upload(self):
  source=self.path('s');source.mkdir()
  for key in ['GITHUB_SHA','RIDES_IOS_UPLOAD','PATH','SEALED_INPUT_PASSPHRASE']:
   with self.subTest(key=key),self.assertRaises(ValueError):prep.prepare(source,[],'driver',secret()|{key:'evil'},self.path('bad-'+key),os.urandom(32),self.git)
 def valid_binding(self):
  e=gh();e.update(SEALED_REVIEWED_HELPER_SHA=e['GITHUB_SHA'],RIDES_IOS_SOURCE_SHA='b'*40,SEALED_REVIEWED_SOURCE_SHA='b'*40,SEALED_REVIEWED_MANIFEST_SHA256='c'*64,SEALED_REVIEWED_ROLE='driver',RIDES_IOS_UPLOAD='false',ASC_APP_ID='6821815632');return e
 def test_public_helper_and_private_snapshot_are_separate_actual_identities(self):
  e=self.valid_binding();binding.validate_context(e,'driver');self.assertNotEqual(e['GITHUB_SHA'],e['RIDES_IOS_SOURCE_SHA'])
 def test_wrong_owner_repo_event_ref_helper_source_role_or_upload_rejected(self):
  for key,value in [('GITHUB_ACTOR','other'),('GITHUB_TRIGGERING_ACTOR','other'),('GITHUB_REPOSITORY','wrong/repo'),('GITHUB_REF','refs/pull/1/head'),('GITHUB_EVENT_NAME','pull_request'),('GITHUB_SHA','d'*40),('RIDES_IOS_SOURCE_SHA','e'*40),('SEALED_REVIEWED_ROLE','customer'),('ASC_APP_ID','6821814203'),('RIDES_IOS_UPLOAD','true')]:
   with self.subTest(key=key),self.assertRaises(ValueError):binding.validate_context(self.valid_binding()|{key:value},'driver')
 def test_child_environment_excludes_every_credential_and_runtime_token(self):
  e=gh()|{'SEALED_INPUT_PASSPHRASE':SENTINEL,'GITHUB_TOKEN':SENTINEL,'ACTIONS_RUNTIME_TOKEN':SENTINEL,'SSH_AUTH_SOCK':SENTINEL,'ASC_PRIVATE_KEY_BASE64':SENTINEL};clean=controller.clean_public_environment(e);self.assertNotIn(SENTINEL,clean.values());self.assertIn('GITHUB_SHA',clean)
 def test_real_child_stdout_is_private_not_parent_stdout(self):
  log=self.path('private.log');public=io.StringIO()
  with contextlib.redirect_stdout(public):code=controller.bounded_process([TEST_PYTHON,'-c','print('+repr(SENTINEL)+')'],controller.clean_public_environment(gh()),self.root,log,timeout=10)
  self.assertEqual(code,0);self.assertNotIn(SENTINEL,public.getvalue());self.assertIn(SENTINEL,log.read_text())
 def test_real_child_timeout_is_bounded(self):
  with self.assertRaises(ValueError):controller.bounded_process([TEST_PYTHON,'-c','import time;time.sleep(30)'],controller.clean_public_environment(gh()),self.root,self.root/'log',timeout=.3)
 def test_posix_descendant_group_is_terminated_even_after_leader_exits(self):
  from unittest.mock import Mock
  p=Mock();p.pid=456789;p.poll.return_value=0;p.wait.return_value=0;live=[True];calls=[]
  def killpg(pid,sig):
   self.assertEqual(pid,456789);calls.append(sig)
   if not live[0]:raise ProcessLookupError()
   if sig==controller.signal.SIGTERM:live[0]=False
  with patch.object(controller.os,'name','posix'),patch.object(controller.os,'killpg',create=True,side_effect=killpg):controller.stop_process(p)
  self.assertIn(controller.signal.SIGTERM,calls);self.assertFalse(live[0])
 def test_posix_zombie_leader_is_reaped_before_group_probe(self):
  from unittest.mock import Mock
  p=Mock();p.pid=456789;state={'terminated':False,'reaped':False};calls=[]
  def poll():
   if state['terminated']:state['reaped']=True;return 0
   return None
  def killpg(pid,sig):
   self.assertEqual(pid,p.pid);calls.append(sig)
   if state['reaped']:raise ProcessLookupError()
   if state['terminated']:raise PermissionError('synthetic-Darwin-zombie-only-group')
   if sig==controller.signal.SIGTERM:state['terminated']=True
  p.poll.side_effect=poll;p.wait.return_value=0
  with patch.object(controller.os,'name','posix'),patch.object(controller.os,'killpg',create=True,side_effect=killpg):controller.stop_process(p)
  self.assertTrue(state['reaped']);self.assertIn(controller.signal.SIGTERM,calls);p.wait.assert_called_once()
 def test_posix_exit_between_reap_poll_and_probe_gets_one_owned_recheck(self):
  from unittest.mock import Mock
  p=Mock();p.pid=456789;state={'zombie':False,'reaped':False};calls=[]
  def poll():
   if state['zombie']:state['reaped']=True;return 0
   return None
  def killpg(pid,sig):
   self.assertEqual(pid,p.pid);calls.append(sig)
   if state['reaped']:raise ProcessLookupError()
   self.assertEqual(sig,0);state['zombie']=True;raise PermissionError('synthetic-exit-after-poll')
  p.poll.side_effect=poll;p.wait.return_value=0
  with patch.object(controller.os,'name','posix'),patch.object(controller.os,'killpg',create=True,side_effect=killpg):controller.stop_process(p)
  self.assertTrue(state['reaped']);self.assertTrue(all(sig==0 for sig in calls));p.wait.assert_called_once()
 def test_posix_persistent_permission_denial_never_claims_quiescence(self):
  from unittest.mock import Mock
  p=Mock();p.pid=456789;p.poll.return_value=0
  with patch.object(controller.os,'name','posix'),patch.object(controller.os,'killpg',create=True,side_effect=PermissionError('synthetic-persistent-denial')) as probe:
   with self.assertRaises(PermissionError):controller.stop_process(p)
  self.assertEqual(probe.call_count,2);p.wait.assert_not_called()
 def test_posix_signal_side_zombie_races_require_proven_group_absence(self):
  from unittest.mock import Mock
  for exiting_signal in [controller.signal.SIGTERM,getattr(controller.signal,'SIGKILL',9)]:
   with self.subTest(signal=exiting_signal):
    p=Mock();p.pid=456789;state={'zombie':False,'reaped':False};calls=[]
    def poll():
     if state['zombie']:state['reaped']=True;return 0
     return None
    def killpg(pid,sig):
     self.assertEqual(pid,p.pid);calls.append(sig)
     if state['reaped']:raise ProcessLookupError()
     if state['zombie']:raise PermissionError('synthetic-zombie-only-group')
     if sig==exiting_signal:state['zombie']=True;raise PermissionError('synthetic-exit-before-signal')
    p.poll.side_effect=poll;p.wait.return_value=0
    with patch.object(controller.signal,'SIGKILL',9,create=True),patch.object(controller.os,'name','posix'),patch.object(controller.os,'killpg',create=True,side_effect=killpg),patch.object(controller.time,'monotonic',side_effect=iter(range(0,256,16))),patch.object(controller.time,'sleep'):
     controller.stop_process(p)
    self.assertTrue(state['reaped']);self.assertIn(exiting_signal,calls);p.wait.assert_called_once()
 def security_fixture(self,shared=False):
  private=self.path('private');(private/'home').mkdir(parents=True);(private/'build-temp').mkdir()
  env={'HOME':str(private/'home'),'PATH':'synthetic'};model=SyntheticSecurity(self.root,private/'home',shared)
  return private,env,model
 def test_default_keychain_absence_accepts_only_recognized_apple_response(self):
  for out,err,code,accepted in [(b'',b'security: SecKeychainCopyDomainDefault user: A default keychain could not be found.\n',1,True),(b' <NULL>\n',b'',0,True),(b'',b'synthetic-unknown-security-error',1,False),(b' /relative/not-quoted\n',b'',1,False)]:
   with self.subTest(response=(out,err,code)),patch.object(controller.subprocess,'run',return_value=subprocess.CompletedProcess([],code,out,err)):
    if accepted:self.assertIsNone(controller.security_default({}))
    else:
     with self.assertRaises(ValueError):controller.security_default({})
 def test_default_keychain_relative_or_ambiguous_path_is_rejected(self):
  for out in [b'"relative/path"',b'"C:/one" "C:/two"',b'"relative\npath"']:
   with self.subTest(response=out),patch.object(controller.subprocess,'run',return_value=subprocess.CompletedProcess([],0,out,b'')):
    with self.assertRaises(ValueError):controller.security_default({})
 def test_private_cms_bootstrap_and_original_state_restore_in_both_domain_models(self):
  for shared in [False,True]:
   with self.subTest(shared=shared):
    case=self.root/str(shared);case.mkdir();private=case/'private';(private/'home').mkdir(parents=True);(private/'build-temp').mkdir();env={'HOME':str(private/'home')};model=SyntheticSecurity(case,private/'home',shared);cms={}
    with patch.object(controller.subprocess,'run',side_effect=model):
     original=controller.security_state({});child=controller.security_state(env);controller.prepare_cms_keychain(private,env,cms)
     self.assertEqual(controller.security_default(env),str(private/'home/cms-bootstrap.keychain-db'))
     self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms));self.assertEqual(controller.security_state({}),original);self.assertEqual(controller.security_state(env),child)
    self.assertFalse((private/'home/cms-bootstrap.keychain-db').exists());self.assertEqual((case/'original-login.keychain-db').read_bytes(),b'KEEP-ORIGINAL-PUBLIC-SYNTHETIC')
 def test_preexisting_bootstrap_is_preserved_without_security_mutation(self):
  private,env,model=self.security_fixture();keychain=private/'home/cms-bootstrap.keychain-db';keychain.write_bytes(b'KEEP-EXISTING');cms={}
  with patch.object(controller.subprocess,'run',side_effect=model):
   with self.assertRaises(ValueError):controller.prepare_cms_keychain(private,env,cms)
  self.assertFalse(model.calls);self.assertEqual(keychain.read_bytes(),b'KEEP-EXISTING');self.assertFalse(cms)
 def test_bootstrap_snapshot_failure_precedes_any_mutation(self):
  private,env,model=self.security_fixture();cms={};model.fail=lambda args,e:True
  with patch.object(controller.subprocess,'run',side_effect=model):
   with self.assertRaises(ValueError):controller.prepare_cms_keychain(private,env,cms)
  self.assertFalse(cms);self.assertFalse(any(c[1]=='create-keychain' for c in model.calls))
 def test_partial_bootstrap_failure_restores_state_and_deletes_only_owned_file(self):
  for failed in ['create-keychain','unlock-keychain','default-keychain','list-keychains']:
   with self.subTest(failed=failed):
    case=self.root/failed;case.mkdir();private=case/'private';(private/'home').mkdir(parents=True);(private/'build-temp').mkdir();env={'HOME':str(private/'home')};model=SyntheticSecurity(case,private/'home');cms={}
    with patch.object(controller.subprocess,'run',side_effect=model):
     original=controller.security_state({});before=controller.security_state(env)
     model.fail=lambda args,e:args[1]==failed and (failed not in {'default-keychain','list-keychains'} or '-s' in args)
     with self.assertRaises(ValueError):controller.prepare_cms_keychain(private,env,cms)
     model.fail=None;self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms));self.assertEqual(controller.security_state(env),before)
    self.assertEqual((case/'original-login.keychain-db').read_bytes(),b'KEEP-ORIGINAL-PUBLIC-SYNTHETIC')
 def test_default_bootstrap_readback_mismatch_stops_before_native_worker(self):
  private,env,model=self.security_fixture();cms={};model.ignore=lambda args,e:args[1]=='default-keychain' and '-s' in args
  # An existing private-HOME default ensures ignored assignment is observable.
  model.child['default']=model.normal['default'];original=copy.deepcopy(model.normal)
  with patch.object(controller.subprocess,'run',side_effect=model):
   with self.assertRaises(ValueError):controller.prepare_cms_keychain(private,env,cms)
   model.ignore=None;self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms))
 def test_failed_default_restore_never_claims_private_cleanup(self):
  private,env,model=self.security_fixture();cms={}
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms)
   model.fail=lambda args,e:args[1:5]==['default-keychain','-d','user','-s'] and e.get('HOME')!=model.home
   self.assertFalse(controller.emergency_signing_cleanup(private,original,{},cms))
 def test_cms_roundtrip_checks_real_darwin_before_any_sealed_input(self):
  private,env,model=self.security_fixture();cms={}
  normal=controller.clean_public_environment(gh());env=normal|{'HOME':str(private/'home')}
  # The production Mac tests the actual OS protocol before input download/decrypt.
  # Windows exercises the same body against explicit synthetic Apple semantics.
  manager=contextlib.nullcontext() if sys.platform=='darwin' else patch.object(controller.subprocess,'run',side_effect=model)
  with manager:
   original=controller.security_state(normal);before=controller.security_state(env)
   try:
    controller.prepare_cms_keychain(private,env,cms)
    self.assertEqual(controller.security_default(env),str(private/'home/cms-bootstrap.keychain-db'))
   finally:
    self.assertTrue(controller.emergency_signing_cleanup(private,original,normal,cms))
   self.assertEqual(controller.security_state(normal),original);self.assertEqual(controller.security_state(env),before)
  self.assertFalse((private/'home/cms-bootstrap.keychain-db').exists())
 def test_pathless_apple_default_setter_does_not_unset_current_default(self):
  private,env,model=self.security_fixture();cms={}
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms)
   result=model(['/usr/bin/security','default-keychain','-d','user','-s'],env=env)
   self.assertEqual(result.returncode,0);self.assertEqual(controller.security_default(env),cms['path'])
   self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms))
 def test_absent_default_is_proved_after_owned_deletion_without_empty_setter(self):
  private,env,model=self.security_fixture();cms={}
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms)
   self.assertIsNone(cms['before']['default'])
   self.assertFalse(controller.restore_security_state(cms['before'],env))
   self.assertTrue(controller.restore_security_state(cms['before'],env,defer_absent=True))
   self.assertEqual(controller.security_default(env),cms['path'])
   self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms));self.assertEqual(controller.security_state(env),cms['before'])
  self.assertFalse(any(c[1:5]==['default-keychain','-d','user','-s'] and len(c)==5 for c in model.calls))
 def test_unowned_default_is_neither_deleted_nor_claimed_restored(self):
  private,env,model=self.security_fixture();cms={};foreign=self.path('foreign.keychain-db');foreign.write_bytes(b'KEEP-FOREIGN')
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms);model.child['default']=str(foreign)
   self.assertFalse(controller.emergency_signing_cleanup(private,original,{},cms))
  self.assertEqual(foreign.read_bytes(),b'KEEP-FOREIGN');self.assertFalse(any(c[1]=='delete-keychain' and c[-1]==str(foreign) for c in model.calls))
 def test_failed_bootstrap_deletion_never_claims_private_cleanup(self):
  private,env,model=self.security_fixture();cms={}
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms);model.fail=lambda args,e:args[1]=='delete-keychain'
   self.assertFalse(controller.emergency_signing_cleanup(private,original,{},cms))
  self.assertTrue((private/'home/cms-bootstrap.keychain-db').exists())
 def test_cleanup_restores_original_after_owned_signing_file_deletion(self):
  private,env,model=self.security_fixture();cms={};signing=private/'build-temp/rouhi-testflight-synthetic/signing.keychain-db';signing.parent.mkdir();signing.write_bytes(b'SYNTHETIC')
  unrelated=self.path('unrelated.keychain-db');unrelated.write_bytes(b'KEEP-UNRELATED')
  with patch.object(controller.subprocess,'run',side_effect=model):
   original=controller.security_state({});controller.prepare_cms_keychain(private,env,cms);model.child['search'].insert(0,str(signing));self.assertTrue(controller.emergency_signing_cleanup(private,original,{},cms))
  self.assertFalse(signing.exists());self.assertEqual(unrelated.read_bytes(),b'KEEP-UNRELATED')
  deletions=[c[-1] for c in model.calls if c[1]=='delete-keychain'];self.assertEqual(set(deletions),{str(signing),str(private/'home/cms-bootstrap.keychain-db')})
 def test_security_restore_failure_is_not_claimed_clean(self):
  private=self.path('private');(private/'build-temp').mkdir(parents=True)
  with patch.object(controller.subprocess,'run',side_effect=OSError('synthetic-security-failure')):self.assertFalse(controller.emergency_signing_cleanup(private,{'default':None,'search':[]},{}))
 def test_cleanup_rejects_a_sibling_instead_of_private_owned_root(self):
  sibling=self.path('valuable');sibling.mkdir();(sibling/'keep').write_bytes(b'keep')
  with self.assertRaises(ValueError):controller.remove_owned_tree(sibling,self.root)
  self.assertEqual((sibling/'keep').read_bytes(),b'keep')
 def test_unconfigured_policy_and_zero_budget_are_rejected(self):
  p=json.loads((Path(__file__).resolve().parents[1]/'policy.json').read_text());p['configured']=False;p['free_artifact_budget_bytes']=0
  with self.assertRaises(ValueError):controller.policy_entry(p,gh())
 def valid_policy(self):
  row={'cipher_sha256':'c'*64,'source_sha':'b'*40,'manifest_sha256':'d'*64,'original_source_closure_sha256':'e'*64,'build_number':'7','version':'1.0','max_ciphertext_output_bytes':1024**2}
  p={'schema':2,'configured':True,'repository':controller.REPO,'output_public_key_sha256':self.pubsha,'free_artifact_budget_bytes':2*1024**2,'inputs':{'customer':row.copy(),'driver':row.copy()}}
  e=gh()|{'REVIEWED_ROLE':'driver','SEALED_INPUT_SHA256':'c'*64,'REVIEWED_SOURCE_SHA':'b'*40,'REVIEWED_BUILD_NUMBER':'7'};return p,e
 def test_exact_two_input_policy_accepts_only_bound_hash_source_and_build(self):
  p,e=self.valid_policy();self.assertEqual(controller.policy_entry(p,e)[0],'driver')
  for key,value in [('REVIEWED_ROLE','third-app'),('SEALED_INPUT_SHA256','f'*64),('REVIEWED_SOURCE_SHA','f'*40),('REVIEWED_BUILD_NUMBER','8')]:
   with self.subTest(key=key),self.assertRaises(ValueError):controller.policy_entry(p,e|{key:value})
 def test_artifact_capacity_cannot_exceed_approved_free_budget(self):
  p,e=self.valid_policy();p['free_artifact_budget_bytes']-=1
  with self.assertRaises(ValueError):controller.policy_entry(p,e)
 def test_third_input_or_unlisted_source_role_not_accepted(self):
  p,e=self.valid_policy();p['inputs']['other']=p['inputs']['driver'].copy()
  with self.assertRaises(ValueError):controller.policy_entry(p,e)
 def test_no_cleanup_or_publish_when_owned_process_group_is_unconfirmed(self):
  out,key,r,raw=self.fixture();helper=self.path('helper');helper.mkdir();(helper/'owner-output-public.pem').write_bytes(self.public);work=self.path('work');work.mkdir(mode=0o700);shutil.copyfile(out/'input.sealed',work/'input.sealed');marker={'synthetic':'owned'};controller.private_json(work/'owner.json',marker)
  row={k:r[k] for k in ['cipher_sha256','source_sha','manifest_sha256','original_source_closure_sha256']};row.update(build_number='7',version='1.0',max_ciphertext_output_bytes=1024**2)
  def unconfirmed(*args,**kwargs):kwargs['process_state'].update(started=True,quiescent=False);raise controller.ProcessGroupStillAlive()
  with patch.dict(adapter.BASELINES,{'driver':hashlib.sha256(raw).hexdigest()}),patch.dict(os.environ,{'SEALED_INPUT_PASSPHRASE':base64.b64encode(key).decode()}),patch.object(controller,'security_state',return_value={'default':None,'search':[]}),patch.object(controller,'prepare_cms_keychain'),patch.object(controller,'emergency_signing_cleanup') as cleanup,patch.object(controller,'bounded_process',side_effect=unconfirmed):
   with self.assertRaises(ValueError):controller.build_and_seal(helper,gh(),self.git,{'output_public_key_sha256':self.pubsha},'driver',row,work,marker)
   cleanup.assert_not_called()
  self.assertTrue((work/'private').exists());self.assertFalse((helper/'sealed-output').exists())
 def test_redirect_cannot_send_request_to_arbitrary_host_or_http(self):
  for url in ['http://github.com/x','https://evil.example/x','https://github.com.evil.example/x','https://user:secret@github.com/x','https://github.com:444/x']:
   with self.subTest(url=url),self.assertRaises(ValueError):controller.safe_url(url)
 def full_run(self,fail=False,clean=True):
  out,key,r,raw=self.fixture(fail=fail);helper=self.path('helper');helper.mkdir();(helper/'owner-output-public.pem').write_bytes(self.public);work=self.path('work');work.mkdir(mode=0o700);shutil.copyfile(out/'input.sealed',work/'input.sealed')
  row={k:r[k] for k in ['cipher_sha256','source_sha','manifest_sha256','original_source_closure_sha256']};row.update(build_number='7',version='1.0',max_ciphertext_output_bytes=1024**2)
  e=gh();marker={'synthetic':'owned'};controller.private_json(work/'owner.json',marker);policy={'output_public_key_sha256':self.pubsha};public=io.StringIO()
  security=SyntheticSecurity(self.root,work/'private/home')
  if not clean:security.fail=lambda args,env:args[1:5]==['default-keychain','-d','user','-s'] and env.get('HOME')!=security.home
  def in_process(args,env,cwd,log,**kwargs):
   self.assertEqual(security.state(env)['default'],str(work/'private/home/cms-bootstrap.keychain-db'))
   self.assertNotIn('RIDES_IOS_P12_PASSWORD',env)
   with Path(log).open('w') as f,patch.dict(os.environ,env,clear=True),contextlib.redirect_stdout(f),contextlib.redirect_stderr(f):return controller.native_worker(args[-1])
  with patch.dict(adapter.BASELINES,{'driver':hashlib.sha256(raw).hexdigest()}),patch.dict(os.environ,{'SEALED_INPUT_PASSPHRASE':base64.b64encode(key).decode()}),patch.object(controller.subprocess,'run',side_effect=security),patch.object(controller,'bounded_process',side_effect=in_process),contextlib.redirect_stdout(public):
   if clean:status=controller.build_and_seal(helper,e,self.git,policy,'driver',row,work,marker)
   else:
    with self.assertRaises(ValueError):controller.build_and_seal(helper,e,self.git,policy,'driver',row,work,marker)
    status=1
  self.assertFalse((work/'private').exists());self.assertNotIn(SENTINEL,public.getvalue());return helper,work,row,e,status
 def test_complete_synthetic_build_encrypts_source_and_logs_never_public_plaintext(self):
  helper,work,row,e,status=self.full_run();self.assertEqual(status,0);self.assertEqual({p.name for p in (helper/'sealed-output').iterdir()},{'payload.sealed','completion.sealed'})
  for p in (helper/'sealed-output').iterdir():self.assertNotIn(SENTINEL.encode(),p.read_bytes())
  context={'role':'driver','source_sha':row['source_sha'],'manifest_sha256':row['manifest_sha256'],'helper_sha':e['GITHUB_SHA'],'run_id':e['GITHUB_RUN_ID'],'kind':'private-native-output'};plain=self.path('owner-only.tar');crypto.open_payload(helper/'sealed-output/payload.sealed',plain,private_pem=self.private,context=context,maximum=1024**2)
  with tarfile.open(plain) as t:
   self.assertIn('native-output/synthetic.ipa',t.getnames());self.assertIn(SENTINEL.encode(),t.extractfile('retained/native-tools.log').read());self.assertFalse(any(name.startswith(('source/','private/')) for name in t.getnames()))
 def test_synthetic_native_failure_has_encrypted_logs_and_false_success(self):
  helper,work,row,e,status=self.full_run(fail=True);self.assertEqual(status,1)
  ctx={'role':'driver','source_sha':row['source_sha'],'manifest_sha256':row['manifest_sha256'],'helper_sha':e['GITHUB_SHA'],'run_id':e['GITHUB_RUN_ID'],'kind':'cleanup-completion'};p=self.path('owner-only-completion.json');crypto.open_payload(helper/'sealed-output/completion.sealed',p,private_pem=self.private,context=ctx,maximum=65536);self.assertFalse(json.loads(p.read_text())['native_build_succeeded'])
 def test_cleanup_failure_never_publishes_ciphertext_as_success(self):
  helper,work,*_=self.full_run(clean=False);self.assertFalse((helper/'sealed-output').exists());self.assertTrue((work/'payload.pending.sealed').exists())

if __name__=='__main__':unittest.main()
