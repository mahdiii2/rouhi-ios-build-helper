"""Owner-only finite sealed build controller. No private repository credential is used."""
import argparse,base64,hashlib,importlib.util,json,os,re,shlex,shutil,signal,stat,subprocess,sys,tarfile,time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,HTTPRedirectHandler,build_opener
from sealed_payload import canonical,digest_file,json_bytes,open_payload,seal_output
from source_snapshot import no_links,extract_payload,git_snapshot,remove_private_tree,verify_source

REPO='mahdiii2/rouhi-ios-build-helper';OWNER='mahdiii2';MAX_INPUT=320*1024**2;MAX_LOG=16*1024**2;MAX_TOOL_LOG=128*1024**2;WORKER_SECONDS=4500
PUBLIC_NAMES={'PATH','JAVA_HOME','DEVELOPER_DIR','ANDROID_HOME','ANDROID_SDK_ROOT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_ARCH','RUNNER_TOOL_CACHE','LANG','LC_ALL','TMPDIR','SYSTEMROOT','SystemRoot','GRADLE_OPTS'}
GH_NAMES={'GITHUB_REPOSITORY','GITHUB_REPOSITORY_OWNER','GITHUB_ACTOR','GITHUB_TRIGGERING_ACTOR','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'}
class Cancelled(Exception):pass
class ProcessGroupStillAlive(Exception):pass
def need(v,code='sealed_controller_guard'):
 if not v:raise ValueError(code)
def private_json(p,v):
 with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(canonical(v));f.flush();os.fsync(f.fileno())
def read_json(p,maximum=4*1024**2):
 p=Path(p);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=maximum);return json_bytes(p.read_bytes())
def clean_public_environment(e):return {k:v for k,v in e.items() if k in PUBLIC_NAMES|GH_NAMES}
def context(e,helper,git):
 need(e.get('GITHUB_REPOSITORY')==REPO and e.get('GITHUB_REPOSITORY_OWNER')==OWNER)
 need(e.get('GITHUB_ACTOR')==e.get('GITHUB_TRIGGERING_ACTOR')==OWNER and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and e.get('GITHUB_REF')=='refs/heads/main')
 need(e.get('GITHUB_RUN_ATTEMPT')=='1' and bool(re.fullmatch('[1-9][0-9]{0,19}',e.get('GITHUB_RUN_ID',''))))
 sha=e.get('REVIEWED_HELPER_SHA','');need(bool(re.fullmatch('[a-f0-9]{40}',sha)) and sha==e.get('GITHUB_SHA'))
 p=subprocess.run([str(git),'rev-parse','HEAD'],cwd=helper,capture_output=True,timeout=15,env=clean_public_environment(e));need(p.returncode==0 and p.stdout.decode().strip()==sha)
 p=subprocess.run([str(git),'status','--porcelain','--untracked-files=no'],cwd=helper,capture_output=True,timeout=15,env=clean_public_environment(e));need(p.returncode==0 and not p.stdout.strip())
 return sha
def policy_entry(policy,e):
 need(set(policy)=={'schema','configured','repository','output_public_key_sha256','free_artifact_budget_bytes','inputs'} and policy['schema']==2 and policy['configured'] is True and policy['repository']==REPO)
 need(set(policy['inputs'])=={'customer','driver'} and type(policy['free_artifact_budget_bytes']) is int and 0<policy['free_artifact_budget_bytes']<=500*1024**2)
 need(bool(re.fullmatch('[a-f0-9]{64}',policy['output_public_key_sha256'])))
 for role,row in policy['inputs'].items():
  need(set(row)=={'cipher_sha256','source_sha','manifest_sha256','original_source_closure_sha256','build_number','version','max_ciphertext_output_bytes'})
  for key in ['cipher_sha256','manifest_sha256','original_source_closure_sha256']:need(bool(re.fullmatch('[a-f0-9]{64}',row[key])))
  need(bool(re.fullmatch('[a-f0-9]{40}',row['source_sha'])) and bool(re.fullmatch(r'[1-9][0-9]{0,3}(?:\.[0-9]{1,2}){0,2}',row['build_number'])) and bool(re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}',row['version'])))
  need(type(row['max_ciphertext_output_bytes']) is int and 1024**2<=row['max_ciphertext_output_bytes']<=250*1024**2)
 need(sum(row['max_ciphertext_output_bytes'] for row in policy['inputs'].values())<=policy['free_artifact_budget_bytes'])
 role=e.get('REVIEWED_ROLE');need(role in policy['inputs']);row=policy['inputs'][role]
 need(e.get('SEALED_INPUT_SHA256')==row['cipher_sha256'] and e.get('REVIEWED_SOURCE_SHA')==row['source_sha'] and e.get('REVIEWED_BUILD_NUMBER')==row['build_number'])
 return role,row
class SafeRedirect(HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  safe_url(newurl);return super().redirect_request(req,fp,code,msg,headers,newurl)
def safe_url(url):
 p=urlsplit(url);need(p.scheme=='https' and p.hostname in {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'} and p.port in {None,443} and p.username is None and p.password is None)
def download_input(dst,sha,opener=None):
 url='https://github.com/'+REPO+'/releases/download/sealed-inputs/input-'+sha+'.sealed';safe_url(url);opener=opener or build_opener(SafeRedirect())
 start=time.monotonic();h=hashlib.sha256();count=0
 with opener.open(Request(url,headers={'User-Agent':'rouhi-sealed-ios-build-helper'}),timeout=30) as response:
  need(response.status==200)
  declared=response.headers.get('Content-Length');need(declared is None or 0<int(declared)<=MAX_INPUT)
  with os.fdopen(os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
   while True:
    need(time.monotonic()-start<=180);b=response.read(1024**2)
    if not b:break
    count+=len(b);need(count<=MAX_INPUT);h.update(b);out.write(b)
   out.flush();os.fsync(out.fileno())
 need(count>0 and h.hexdigest()==sha)
def owned_work(temp,e,role):
 temp=Path(temp);need(temp.is_absolute() and temp.resolve(strict=True)==temp);no_links(temp,temp)
 return temp/('rouhi-sealed-'+e['GITHUB_RUN_ID']+'-'+role)
def verify_work(work,expected):
 no_links(work,work);need(work.is_dir() and read_json(work/'owner.json')==expected)
 if hasattr(os,'getuid'):need(work.stat().st_uid==os.getuid() and stat.S_IMODE(work.stat().st_mode)==0o700)
def actual_tools(e,helper):
 need(sys.platform=='darwin' and e.get('RUNNER_ENVIRONMENT')=='github-hosted' and e.get('RUNNER_ARCH')=='X64' and e.get('RUNNER_OS')=='macOS')
 git=Path('/usr/bin/git');need(git.is_file() and Path(e.get('DEVELOPER_DIR','')).as_posix()=='/Applications/Xcode_26.3.app/Contents/Developer')
 need(sys.version_info[:2]==(3,12))
 memory=int(subprocess.check_output(['/usr/sbin/sysctl','-n','hw.memsize'],timeout=10));need(memory>=12*1024**3)
 need(shutil.disk_usage(Path(e['RUNNER_TEMP'])).free>=12*1024**3)
 for args in [['/usr/bin/xcodebuild','-version'],['/usr/bin/xcrun','--sdk','iphoneos','--show-sdk-version']]:
  out=subprocess.check_output(args,timeout=20,env=clean_public_environment(e)).decode();need((int(out.splitlines()[0].split()[1].split('.')[0]) if len(args)==2 else int(out.strip().split('.')[0]))>=26)
 java=Path(e.get('JAVA_HOME',''))/'bin/java';need(java.is_file())
 need(b'version "21.' in subprocess.run([str(java),'-version'],capture_output=True,timeout=20).stderr)
 sdk=Path(e.get('ANDROID_HOME',''));need(sdk.is_absolute())
 for rel in ['platforms/android-35/android.jar','platforms/android-36/android.jar','build-tools/36.0.0/aapt2']:need((sdk/rel).is_file())
 need(shutil.which('pod') is not None)
 return git
def stop_process(p):
 if p is None:return
 if os.name=='posix':
  # A dead/reaped leader does not prove its Gradle/compiler descendants exited.
  # This PGID is exclusively created by our start_new_session Popen below.
  def alive():
   # Darwin can report EPERM for a group containing only an unreaped zombie.
   # Reap only our child; leader exit never replaces probing its whole group.
   p.poll()
   try:os.killpg(p.pid,0);return True
   except ProcessLookupError:return False
   except PermissionError:
    # Close exit-between-poll-and-probe once; persistent denial stays uncertain.
    p.poll()
    try:os.killpg(p.pid,0);return True
    except ProcessLookupError:return False
  if alive():
   try:os.killpg(p.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   except PermissionError:
    # The leader may exit after a positive probe but before the signal.
    # Ignore denial only after proving the whole owned group is now absent.
    if alive():raise
  deadline=time.monotonic()+15
  while alive() and time.monotonic()<deadline:
   p.poll();time.sleep(.1)
  if alive():
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   except PermissionError:
    # The leader may exit after a positive probe but before the signal.
    # Ignore denial only after proving the whole owned group is now absent.
    if alive():raise
  deadline=time.monotonic()+15
  while alive() and time.monotonic()<deadline:
   p.poll();time.sleep(.1)
  if alive():raise ProcessGroupStillAlive()
  p.wait(timeout=1)
 else:
  # Windows is synthetic-test support only; production is actual Darwin.
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=15)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=15)
  need(p.poll() is not None)
def bounded_process(args,env,cwd,log,*,timeout=WORKER_SECONDS,extra_logs=None,process_state=None):
 """Never sends a child byte to the public log; kills its owned process group."""
 p=None;start=time.monotonic();process_state=process_state if process_state is not None else {};process_state.update(started=False,quiescent=True)
 try:
  with os.fdopen(os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
   p=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=os.name=='posix')
   process_state.update(started=True,quiescent=False)
   while p.poll() is None:
    need(time.monotonic()-start<timeout,'native_process_timeout');need(Path(log).stat().st_size<=MAX_LOG,'private_log_budget_exceeded')
    if extra_logs:
     for f in Path(extra_logs).glob('rouhi-testflight-*/tools.log'):
      no_links(f,extra_logs);need(f.stat().st_size<=MAX_TOOL_LOG,'native_log_budget_exceeded')
    time.sleep(.2)
   need(Path(log).stat().st_size<=MAX_LOG);return p.returncode
 finally:
  stop_process(p);process_state['quiescent']=True
def security_list(env):
 p=subprocess.run(['/usr/bin/security','list-keychains','-d','user'],env=env,capture_output=True,timeout=30);need(p.returncode==0 and len(p.stdout)<=65536)
 rows=shlex.split(p.stdout.decode());need(len(rows)<=32 and all(Path(x).is_absolute() and '\n' not in x and '\r' not in x for x in rows));return rows
def security_default(env):
 p=subprocess.run(['/usr/bin/security','default-keychain','-d','user'],env=env,capture_output=True,stdin=subprocess.DEVNULL,timeout=30)
 need(len(p.stdout)<=65536 and len(p.stderr)<=65536)
 if p.returncode==1 and not p.stdout.strip() and re.fullmatch(r'(?:security: )?SecKeychainCopyDomainDefault user: A default keychain could not be found\.',p.stderr.decode().strip()):return None
 need(p.returncode==0)
 if p.stdout.strip()==b'<NULL>':return None
 rows=shlex.split(p.stdout.decode());need(len(rows)==1 and Path(rows[0]).is_absolute() and '\n' not in rows[0] and '\r' not in rows[0]);return rows[0]

def security_state(env):return {'default':security_default(env),'search':security_list(env)}

def restore_security_state(state,env,*,defer_absent=False):
 # Empty search lists fall back to the still-present default on Darwin.
 # SecKeychainDelete clears our owned default/list entry; the caller verifies
 # BOTH full states after every owned deletion before claiming cleanup.
 if defer_absent and state['default'] is None:return True
 good=True
 # Apple's pathless default setter resolves the CURRENT default; it cannot unset.
 # An originally absent default is proved only after deleting our owned keychains.
 commands=([['default-keychain','-d','user','-s',state['default']]] if state['default'] is not None else [])
 commands.append(['list-keychains','-d','user','-s',*state['search']])
 for args in commands:
  try:
   p=subprocess.run(['/usr/bin/security',*args],env=env,capture_output=True,stdin=subprocess.DEVNULL,timeout=30);need(p.returncode==0)
  except BaseException:good=False
 if defer_absent:return good
 try:
  actual=security_state(env);need(actual==state)
 except BaseException:good=False
 return good

def prepare_cms_keychain(private,env,state):
 """Give unchanged CMS verification a private default for public signer certs."""
 home=private/'home';no_links(home,private);need(home.is_dir() and env['HOME']==str(home))
 keychain=home/'cms-bootstrap.keychain-db';no_links(keychain,private);need(not keychain.exists() and not state)
 # Security's preferences writer silently ignores a missing parent directory.
 # These directories belong only to this newly created private HOME.
 for rel in ['Library','Library/Preferences','Library/Keychains']:
  parent=home/rel;no_links(parent,private)
  if not parent.exists():parent.mkdir(mode=0o700)
  need(parent.is_dir())
 # Capture before create: Security may make the first keychain default itself.
 state.update(before=security_state(env),environment=env.copy(),path=str(keychain),attempted=True)
 password=base64.b64encode(os.urandom(32)).decode()
 try:
  for args in [['create-keychain','-p',password,str(keychain)],['unlock-keychain','-p',password,str(keychain)],['default-keychain','-d','user','-s',str(keychain)],['list-keychains','-d','user','-s',str(keychain),*state['before']['search']]]:
   p=subprocess.run(['/usr/bin/security',*args],env=env,capture_output=True,stdin=subprocess.DEVNULL,timeout=30);need(p.returncode==0)
  no_links(keychain,private);need(keychain.is_file())
  actual=security_state(env);need(actual['default']==str(keychain),'cms_default_readback_mismatch');need(actual['search']==[str(keychain),*state['before']['search']],'cms_search_readback_mismatch')
 finally:password=None

def emergency_signing_cleanup(private,original_state,env,cms=None):
 """Only keys/profiles beneath private HOME/temp can have been installed."""
 if original_state is None:return True
 good=True
 cms=cms or {};childenv=cms.get('environment',env)
 # Workers are already quiescent. Restore before deleting any default keychain.
 if cms.get('attempted') and not restore_security_state(cms['before'],childenv,defer_absent=True):good=False
 for p in (private/'build-temp').glob('rouhi-testflight-*/signing.keychain-db'):
  try:
   no_links(p,private);need(p.parent.parent==private/'build-temp' and p.parent.name.startswith('rouhi-testflight-'))
   result=subprocess.run(['/usr/bin/security','delete-keychain',str(p)],env=childenv,capture_output=True,stdin=subprocess.DEVNULL,timeout=30);need(result.returncode==0 and not p.exists())
  except BaseException:good=False
 if cms.get('attempted'):
  try:
   p=Path(cms['path']);need(p==private/'home/cms-bootstrap.keychain-db');no_links(p,private)
   if p.exists():
    result=subprocess.run(['/usr/bin/security','delete-keychain',str(p)],env=childenv,capture_output=True,stdin=subprocess.DEVNULL,timeout=30);need(result.returncode==0 and not p.exists())
  except BaseException:good=False
 if not restore_security_state(original_state,env):good=False
 if cms.get('attempted'):
  try:need(security_state(childenv)==cms['before'])
  except BaseException:good=False
 return good

def remove_owned_tree(path,root):
 path=Path(path);root=Path(root);need(path.parent==root and path.name=='private');no_links(path,root)
 # Check all paths before deletion; source build output links are unlinked by
 # shutil without traversal, but a replaced top-level root is never followed.
 identity=path.stat();need(path.resolve(strict=True)==path and stat.S_ISDIR(identity.st_mode));remove_private_tree(path);need(not path.exists())
def add_regular(tar,p,name,root,maximum):
 no_links(p,root);need(p.is_file() and p.stat().st_size<=maximum)
 with p.open('rb') as f:
  info=tarfile.TarInfo(name);info.size=p.stat().st_size;info.mode=0o600;tar.addfile(info,f)
def native_worker(config_path):
 """Runs only inside the controller's private process/log boundary."""
 c=read_json(config_path,20*1024**2);need(set(c)=={'private','environment'});private=Path(c['private']);need(Path(config_path)==private/'worker-config.json');source=private/'unpacked/source';no_links(source,private)
 import sealed_ios_context
 e=c['environment'];role=e['SEALED_REVIEWED_ROLE'];sealed_ios_context.validate_context(e,role)
 need(e['HOME']==str(private/'home') and e['RUNNER_TEMP']==str(private/'build-temp') and 'SEALED_INPUT_PASSPHRASE' not in e)
 m=read_json(private/'unpacked/manifest.json');need(digest_file(private/'unpacked/manifest.json')==e['SEALED_REVIEWED_MANIFEST_SHA256']);verify_source(source,m['files'],allow_git=True)
 need(digest_file(source/'tools/build_testflight.py')==m['native_builder_adapted_sha256'])
 p=subprocess.run([shutil.which('git'),'rev-parse','HEAD'],cwd=source,capture_output=True,timeout=15);need(p.returncode==0 and p.stdout.decode().strip()==e['RIDES_IOS_SOURCE_SHA'])
 sys.modules['sealed_ios_context']=sealed_ios_context;sys.path.insert(0,str(source/'tools'))
 s=importlib.util.spec_from_file_location('sealed_owned_native_builder',source/'tools/build_testflight.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
 original=b.cleanup_owned_inputs;cleanup={'called':False,'verified':False}
 def retain_and_cleanup(*args,**kwargs):
  cleanup['called']=True;retained_error=False
  try:
   log=args[0]/'tools.log'
   if log.exists():
    no_links(log,private);need(log.stat().st_size<=MAX_TOOL_LOG)
    with log.open('rb') as f:
     f.seek(max(0,log.stat().st_size-8*1024**2));data=f.read(8*1024**2)
    retained=private/'retained/native-tools.log'
    with os.fdopen(os.open(retained,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(data)
  except BaseException:retained_error=True
  finally:
   original(*args,**kwargs);cleanup['verified']=True
  need(not retained_error,'private_log_retention_failed')
 b.cleanup_owned_inputs=retain_and_cleanup;ok=False;category='native_failure'
 try:
  b.build(c['environment']);ok=True;category='native_succeeded'
 except BaseException:category='native_failed'
 finally:private_json(private/'worker-result.json',{'schema':2,'native_succeeded':ok,'category':category,'native_cleanup':cleanup})
 return 0 if ok else 1
def preflight(helper,e,git,policy,role,row,work,marker):
 need(not work.exists());work.mkdir(mode=0o700);private_json(work/'owner.json',marker)
 download_input(work/'input.sealed',row['cipher_sha256']);print('Sealed input preflight passed.')
def build_and_seal(helper,e,git,policy,role,row,work,marker):
 verify_work(work,marker);need(digest_file(work/'input.sealed')==row['cipher_sha256']);private_json(work/'build-started.json',{'started':True})
 key_text=os.environ.pop('SEALED_INPUT_PASSPHRASE','');key=base64.b64decode(key_text,validate=True);del key_text;need(len(key)==32)
 public_path=helper/'owner-output-public.pem';no_links(public_path,helper);public=public_path.read_bytes();need(hashlib.sha256(public).hexdigest()==policy['output_public_key_sha256'])
 private=work/'private';private.mkdir(mode=0o700);search=None;cms={};native=False;signing_clean=False;cipher=None;error='native_not_started';process_state={'started':False,'quiescent':True}
 pubenv=clean_public_environment(e);pubenv.pop('RUNNER_TEMP',None)
 try:
  payload_context={'role':role,'source_sha':row['source_sha'],'manifest_sha256':row['manifest_sha256']}
  open_payload(work/'input.sealed',private/'input.tar',context=payload_context,maximum=MAX_INPUT,key=key);del key
  unpacked=private/'unpacked';unpacked.mkdir(mode=0o700);m,secret=extract_payload(private/'input.tar',unpacked,payload_context,row['manifest_sha256'])
  need(m['original_source_closure_sha256']==row['original_source_closure_sha256'] and secret['RIDES_IOS_BUILD_NUMBER']==row['build_number'] and secret['RIDES_IOS_VERSION']==row['version'])
  for name in ['home','git-home','build-temp','retained']:(private/name).mkdir(mode=0o700)
  need(git_snapshot(unpacked/'source',m['files'],git,private/'git-home')==row['source_sha'])
  verify_source(unpacked/'source',m['files'],allow_git=True)
  childenv=pubenv|{'HOME':str(private/'home'),'RUNNER_TEMP':str(private/'build-temp'),'TMPDIR':str(private/'build-temp'),'PYTHONDONTWRITEBYTECODE':'1','GRADLE_USER_HOME':str(private/'home/.gradle'),'KONAN_DATA_DIR':str(private/'home/.konan'),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
  buildenv=childenv|secret|{'RIDES_IOS_CONTEXT':'sealed-helper-v2','RIDES_IOS_UPLOAD':'false','RIDES_IOS_SOURCE_SHA':row['source_sha'],'SEALED_REVIEWED_HELPER_SHA':e['GITHUB_SHA'],'SEALED_REVIEWED_SOURCE_SHA':row['source_sha'],'SEALED_REVIEWED_MANIFEST_SHA256':row['manifest_sha256'],'SEALED_REVIEWED_ROLE':role}
  secret.clear();search=security_state(pubenv);prepare_cms_keychain(private,childenv,cms)
  private_json(private/'worker-config.json',{'private':str(private),'environment':buildenv});buildenv.clear()
  status=bounded_process([sys.executable,'-B',str(Path(__file__)),'worker',str(private/'worker-config.json')],childenv,unpacked/'source',private/'worker.log',extra_logs=private/'build-temp',process_state=process_state)
  result=read_json(private/'worker-result.json');need(set(result)=={'schema','native_succeeded','category','native_cleanup'} and result['schema']==2)
  need(status==0 and result['native_succeeded'] is True and result['native_cleanup']=={'called':True,'verified':True})
  receipt=read_json(unpacked/'source/build/testflight-output/receipt.json');need(receipt['private_signing_cleanup_verified'] is True and receipt['apple_binary_validation_succeeded'] is True and receipt['upload_command_succeeded'] is False and receipt['public_submission_performed'] is False and receipt['source_sha']==row['source_sha'])
  native=True;error='none'
 except BaseException as exc:
  error='cancelled' if isinstance(exc,Cancelled) else 'build_failed';native=False
 finally:
  # On uncertain child lifetime preserve the exact private directory for the
  # disposable VM; never remove keys or claim/publish cleanup completion.
  need(process_state['quiescent'],'owned_process_group_not_quiescent')
  signing_clean=emergency_signing_cleanup(private,search,pubenv,cms)
  try:
   private_json(private/'controller-result.json',{'schema':2,'native_build_succeeded':native,'native_failure_category':error,'outer_signing_cleanup_verified':signing_clean,'public_upload':False,'testflight_processing':False,'device_verified':False,'full_attestation':False})
   archive=private/'output.tar'
   with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as t:
    add_regular(t,private/'controller-result.json','controller-result.json',private,65536)
    for name in ['worker-result.json','worker.log','retained/native-tools.log']:
     p=private/name
     if p.exists():add_regular(t,p,name,private,MAX_LOG)
    if native:
     out=private/'unpacked/source/build/testflight-output';no_links(out,private);files=list(out.iterdir());need(len(files)==3 and sum(x.suffix=='.ipa' for x in files)==1 and {x.name for x in files if x.suffix!='.ipa'}=={'Podfile.lock','receipt.json'})
     for p in files:add_regular(t,p,'native-output/'+p.name,private,row['max_ciphertext_output_bytes'])
   outcontext={'role':role,'source_sha':row['source_sha'],'manifest_sha256':row['manifest_sha256'],'helper_sha':e['GITHUB_SHA'],'run_id':e['GITHUB_RUN_ID'],'kind':'private-native-output'}
   cipher=work/'payload.pending.sealed';seal_output(archive,cipher,public,policy['output_public_key_sha256'],outcontext,row['max_ciphertext_output_bytes']-65536)
  finally:remove_owned_tree(private,work)
 need(signing_clean and not private.exists() and cipher is not None and cipher.is_file(),'private_cleanup_unverified')
 completion={'schema':2,'payload_cipher_sha256':digest_file(cipher),'native_build_succeeded':native,'private_directory_removed':True,'outer_signing_cleanup_verified':True,'public_upload':False,'testflight_processing':False,'device_verified':False,'full_attestation':False}
 private_json(work/'completion.private.json',completion)
 try:
  cc=work/'completion.pending.sealed';seal_output(work/'completion.private.json',cc,public,policy['output_public_key_sha256'],outcontext|{'kind':'cleanup-completion'},65536)
 finally:(work/'completion.private.json').unlink(missing_ok=True)
 need(cipher.stat().st_size+cc.stat().st_size<=row['max_ciphertext_output_bytes'])
 output=helper/'sealed-output';need(not output.exists());output.mkdir(mode=0o700);no_links(output,helper)
 for original,name in [(cipher,'payload.sealed'),(cc,'completion.sealed')]:
  target=output/name;shutil.copyfile(original,target);need(digest_file(target)==digest_file(original))
 print('Sealed output prepared; private cleanup verified.')
 return 0 if native else 1
def final_cleanup(helper,e,role,work,marker):
 verify_work(work,marker);need(not (work/'private').exists())
 # No recursive deletion outside this exact owned run folder or output folder.
 no_links(work,work);shutil.rmtree(work)
 output=helper/'sealed-output'
 if output.exists():
  no_links(output,helper);need({p.name for p in output.iterdir()}<={'payload.sealed','completion.sealed'})
  for p in output.iterdir():no_links(p,output);need(p.is_file());p.unlink()
  output.rmdir()
def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['preflight','build-and-seal','final-cleanup','worker']);p.add_argument('worker_config',nargs='?');a=p.parse_args()
 if a.mode=='worker':return native_worker(a.worker_config)
 e=dict(os.environ);helper=Path(__file__).resolve().parents[1];no_links(helper/'policy.json',helper);policy=read_json(helper/'policy.json')
 git=Path('/usr/bin/git') if a.mode=='final-cleanup' else actual_tools(e,helper)
 sha=context(e,helper,git);role,row=policy_entry(policy,e)
 work=owned_work(Path(e['RUNNER_TEMP']),e,role);marker={'schema':2,'role':role,'run_id':e['GITHUB_RUN_ID'],'helper_sha':sha,'cipher_sha256':row['cipher_sha256'],'policy_sha256':digest_file(helper/'policy.json')}
 if a.mode=='preflight':preflight(helper,e,git,policy,role,row,work,marker);return 0
 if a.mode=='final-cleanup':final_cleanup(helper,e,role,work,marker);return 0
 return build_and_seal(helper,e,git,policy,role,row,work,marker)
if __name__=='__main__':
 os.umask(0o077)
 def cancelled(*_):raise Cancelled()
 for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,cancelled)
 try:raise SystemExit(main())
 except SystemExit:raise
 except BaseException:print('Sealed build stopped; no raw private output published.',file=sys.stderr);raise SystemExit(1) from None
