"""Explicit source-manifest input only. Default CLI is inert. Never reads a key path."""
import argparse,base64,hashlib,json,os,shutil,tarfile,tempfile
from pathlib import Path
from context_adapter import BASELINES,adapt
from sealed_payload import canonical,digest_file,seal_input
from source_snapshot import PRIVATE_KEYS,closure,git_snapshot,no_links,remove_private_tree,validate_rows,verify_source

def need(v):
 if not v:raise ValueError('payload_preparation_invalid')
def prepare(source,rows,role,private_environment,out,key,git):
 """Caller must separately authorize exact real source/config inputs before use."""
 source=Path(source);out=Path(out);need(source.is_absolute() and source.resolve(strict=True)==source and out.is_absolute() and out.parent.resolve(strict=True)==out.parent)
 need(role in BASELINES and not out.exists() and source not in out.parents and set(private_environment)==PRIVATE_KEYS)
 validate_rows(rows);out.mkdir(mode=0o700);stage=out/'private';stage.mkdir(mode=0o700)
 try:
  target=stage/'source';target.mkdir(mode=0o700)
  for row in rows:
   src=source/row['path'];no_links(src,source);need(src.is_file() and src.stat().st_size==row['size'] and digest_file(src)==row['sha256'])
   dst=target/row['path'];dst.parent.mkdir(parents=True,mode=0o700,exist_ok=True);shutil.copyfile(src,dst);dst.chmod(row['mode'])
  original_closure=closure(rows);builder=target/'tools/build_testflight.py';raw=builder.read_bytes();changed=adapt(raw,role);builder.write_bytes(changed)
  final=[]
  for row in rows:
   p=target/row['path'];final.append(row|{'size':p.stat().st_size,'sha256':digest_file(p)})
  home=stage/'git-home';home.mkdir(mode=0o700);commit=git_snapshot(target,final,git,home)
  env_raw=canonical(private_environment)
  manifest={'schema':2,'role':role,'source_sha':commit,'source_closure_sha256':closure(final),'original_source_closure_sha256':original_closure,'source_provenance':'generated-snapshot-from-reviewed-files','files':final,'private_environment_sha256':hashlib.sha256(env_raw).hexdigest(),'native_builder_original_sha256':BASELINES[role],'native_builder_adapted_sha256':hashlib.sha256(changed).hexdigest()}
  manifest_raw=canonical(manifest);manifest_sha=hashlib.sha256(manifest_raw).hexdigest()
  archive=stage/'input.tar'
  with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tar:
   import io
   for name,data,mode in [('manifest.json',manifest_raw,0o600),('private/environment.json',env_raw,0o600)]:
    info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;tar.addfile(info,io.BytesIO(data))
   for row in final:
    p=target/row['path'];info=tarfile.TarInfo('source/'+row['path']);info.size=p.stat().st_size;info.mode=row['mode']
    with p.open('rb') as f:tar.addfile(info,f)
  context={'role':role,'source_sha':commit,'manifest_sha256':manifest_sha};result=seal_input(archive,out/'input.sealed',key,context,320*1024**2)
  receipt={'schema':2,'role':role,'cipher_sha256':result['sha256'],'cipher_bytes':result['bytes'],'source_sha':commit,'manifest_sha256':manifest_sha,'original_source_closure_sha256':original_closure,'source_closure_sha256':manifest['source_closure_sha256'],'source_provenance':manifest['source_provenance'],'private_inputs_published':False,'upload':False}
  (out/'local-private-preparation-receipt.json').write_bytes(canonical(receipt));(out/'local-private-adapter-before.py').write_bytes(raw);(out/'local-private-adapter-after.py').write_bytes(changed)
  return receipt
 finally:
  need(stage.parent==out and stage.name=='private');no_links(stage,out);remove_private_tree(stage);need(not stage.exists())
def main():
 p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--source');p.add_argument('--manifest');p.add_argument('--private-environment');p.add_argument('--output');p.add_argument('--role',choices=['customer','driver']);a=p.parse_args()
 if not a.execute:print(json.dumps({'plan_only':True,'actions':0,'real_private_inputs_read':False}));return
 # Explicit paths only; no default workspace, keychain, Git config or home scan.
 from sealed_payload import json_bytes
 spec=json_bytes(Path(a.manifest).read_bytes());private=json_bytes(Path(a.private_environment).read_bytes());key=base64.b64decode(os.environ.pop('SEALED_INPUT_PASSPHRASE'),validate=True);need(len(key)==32)
 result=prepare(Path(a.source),spec['files'],a.role,private,Path(a.output),key,shutil.which('git'));print(json.dumps({'prepared_cipher_sha256':result['cipher_sha256'],'source_sha':result['source_sha'],'uploaded':False}))
if __name__=='__main__':
 os.umask(0o077)
 try:main()
 except BaseException:print('Payload preparation stopped; details withheld.');raise SystemExit(1) from None
