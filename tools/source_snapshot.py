"""Strict non-link extraction and reproducible generated Git snapshot identity."""
import hashlib,json,os,re,shutil,stat,subprocess,tarfile,unicodedata
from pathlib import Path,PurePosixPath
from sealed_payload import canonical,digest_file,json_bytes
from context_adapter import BASELINES,NEW,OLD,adapt

MAX_FILES=2500;MAX_SOURCE_BYTES=256*1024*1024;MAX_MEMBER=64*1024*1024
SNAPSHOT_DATE='2000-01-01T00:00:00+00:00';SNAPSHOT_MESSAGE='Generated reviewed sealed iOS source snapshot v2'
PRIVATE_KEYS=frozenset({'RIDES_IOS_P12_BASE64','RIDES_IOS_P12_PASSWORD','RIDES_IOS_PROFILE_BASE64','RIDES_IOS_FIREBASE_PLIST_BASE64','RIDES_IOS_PROVIDER_XCCONFIG_BASE64','RIDES_IOS_PROVIDER_EVIDENCE_BASE64','ASC_PRIVATE_KEY_BASE64','ASC_KEY_ID','ASC_ISSUER_ID','ASC_APP_ID','RIDES_IOS_BUILD_NUMBER','RIDES_IOS_VERSION'})
def need(v):
 if not v:raise ValueError('source_snapshot_invalid')
def path_name(value):
 need(isinstance(value,str) and 0<len(value)<=1024 and '\\' not in value and ':' not in value and all(ord(c)>=32 and ord(c)!=127 for c in value))
 p=PurePosixPath(value);need(not p.is_absolute() and str(p)==value and all(x not in {'','.','..'} and x.casefold()!='.git' and not x.endswith(('.', ' ')) for x in p.parts));need(unicodedata.normalize('NFC',value)==value)
 return value
def no_links(p,root):
 p=Path(p);root=Path(root);need(p==root or root in p.parents)
 for current in [p,*p.parents]:
  if current.exists() or current.is_symlink():
   s=current.lstat();need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&1024)
  if current==root:break
def remove_private_tree(root):
 """Delete a caller-verified private root; handle readonly Git objects on Windows."""
 root=Path(root);need(root.resolve(strict=True)==root and root.is_dir());no_links(root,root)
 def readonly_retry(function,path,error):
  p=Path(path);need(os.name=='nt' and isinstance(error,PermissionError) and root in p.parents)
  no_links(p,root);need(p.is_file());p.chmod(stat.S_IREAD|stat.S_IWRITE);function(path)
 shutil.rmtree(root,onexc=readonly_retry);need(not root.exists())
def validate_rows(rows):
 need(isinstance(rows,list) and 1<=len(rows)<=MAX_FILES);seen=set();total=0
 for row in rows:
  need(set(row)=={'path','sha256','size','mode'});name=path_name(row['path']);alias=name.casefold();need(alias not in seen);seen.add(alias)
  need(re.fullmatch('[a-f0-9]{64}',row['sha256']) and type(row['size']) is int and 0<=row['size']<=MAX_MEMBER and row['mode'] in [0o644,0o755]);total+=row['size']
 need(total<=MAX_SOURCE_BYTES and [r['path'] for r in rows]==sorted(r['path'] for r in rows))
 return rows
def closure(rows):return hashlib.sha256(canonical(validate_rows(rows))).hexdigest()
def verify_source(root,rows,allow_git=False):
 root=Path(root);no_links(root,root);actual=[]
 for p in root.rglob('*'):
  rel=p.relative_to(root).as_posix()
  if allow_git and rel.split('/')[0]=='.git':continue
  no_links(p,root)
  if p.is_file():actual.append(rel)
  else:need(p.is_dir())
 need(sorted(actual)==[r['path'] for r in validate_rows(rows)])
 for r in rows:
  p=root/r['path'];need(p.stat().st_size==r['size'] and digest_file(p)==r['sha256'])
def validate_manifest(m,context):
 need(isinstance(m,dict) and set(m)=={'schema','role','source_sha','source_closure_sha256','original_source_closure_sha256','source_provenance','files','private_environment_sha256','native_builder_original_sha256','native_builder_adapted_sha256'})
 need(m['schema']==2 and m['role']==context['role'] and m['source_sha']==context['source_sha'])
 need(m['source_provenance']=='generated-snapshot-from-reviewed-files' and m['source_closure_sha256']==closure(m['files']))
 for key in ['original_source_closure_sha256','private_environment_sha256','native_builder_adapted_sha256']:need(bool(re.fullmatch('[a-f0-9]{64}',m[key])))
 need(m['native_builder_original_sha256']==BASELINES[m['role']])
def extract_payload(archive,dest,context,manifest_sha):
 """No files written until every archive header/name and manifest are checked."""
 dest=Path(dest);need(dest.is_dir() and not list(dest.iterdir()));no_links(dest,dest)
 with tarfile.open(archive,'r:') as t:
  # The preparer emits uncompressed USTAR. No compressed archive expansion.
  members=[];names=[];total=0
  for member in t:
   members.append(member);need(len(members)<=MAX_FILES+2)
   name=path_name(member.name);need(member.isfile() and not member.issym() and not member.islnk() and not member.pax_headers and 0<=member.size<=MAX_MEMBER and member.mode in [0o600,0o644,0o755]);names.append(name)
   total+=member.size;need(total<=MAX_SOURCE_BYTES+20*1024**2)
  need(len(members)>=3 and len({x.casefold() for x in names})==len(names) and names.count('manifest.json')==1 and names.count('private/environment.json')==1 and t.getmember('private/environment.json').size<=16*1024**2)
  item=t.getmember('manifest.json');need(item.size<=4*1024*1024);raw=t.extractfile(item).read();need(hashlib.sha256(raw).hexdigest()==manifest_sha)
  m=json_bytes(raw);validate_manifest(m,context);need(set(names)=={'manifest.json','private/environment.json'}|{'source/'+r['path'] for r in m['files']})
  rows={'source/'+r['path']:r for r in m['files']}
  for member in members:
   expected=rows.get(member.name)
   if expected:need(member.size==expected['size'] and member.mode==expected['mode'])
  for member in members:
   p=dest/member.name;p.parent.mkdir(parents=True,mode=0o700,exist_ok=True);no_links(p.parent,dest)
   descriptor=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   h=hashlib.sha256();copied=0
   with os.fdopen(descriptor,'wb') as out:
    inp=t.extractfile(member)
    while True:
     b=inp.read(1024*1024)
     if not b:break
     copied+=len(b);need(copied<=member.size);h.update(b);out.write(b)
   need(copied==member.size)
   expected=rows.get(member.name)
   if expected:need(h.hexdigest()==expected['sha256']);p.chmod(expected['mode'])
  private=dest/'private/environment.json';need(private.stat().st_size<=16*1024*1024 and digest_file(private)==m['private_environment_sha256'])
  e=json_bytes(private.read_bytes());need(isinstance(e,dict) and set(e)==PRIVATE_KEYS and all(isinstance(v,str) and 0<len(v)<=12*1024*1024 for v in e.values()))
  need(e['ASC_APP_ID']=={'customer':'6821814203','driver':'6821815632'}[m['role']])
  source=dest/'source';verify_source(source,m['files'])
  builder=source/'tools/build_testflight.py';need(digest_file(builder)==m['native_builder_adapted_sha256'])
  text=builder.read_text();need(text.count(NEW)==1);old=text.replace(NEW,OLD,1).encode();need(hashlib.sha256(old).hexdigest()==BASELINES[m['role']] and adapt(old,m['role'])==builder.read_bytes())
  need(not (source/'tools/sealed_ios_context.py').exists())
  return m,e
def git_snapshot(root,rows,git,private_home):
 root=Path(root);verify_source(root,rows)
 env={k:v for k,v in os.environ.items() if k in {'PATH','SYSTEMROOT','SystemRoot','TEMP','TMP'}}
 env.update(HOME=str(private_home),GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_TERMINAL_PROMPT='0',GIT_AUTHOR_NAME='Rouhi generated snapshot',GIT_AUTHOR_EMAIL='generated-snapshot@invalid',GIT_COMMITTER_NAME='Rouhi generated snapshot',GIT_COMMITTER_EMAIL='generated-snapshot@invalid',GIT_AUTHOR_DATE=SNAPSHOT_DATE,GIT_COMMITTER_DATE=SNAPSHOT_DATE)
 def call(args,data=None):
  p=subprocess.run([str(git),'-c','core.hooksPath='+os.devnull,'-c','core.autocrlf=false','-c','core.filemode=false',*args],cwd=root,input=data,env=env,capture_output=True,timeout=60)
  need(p.returncode==0);return p.stdout
 call(['init','--quiet','--object-format=sha1','-b','sealed-source']);call(['add','--force','--all','--','.'])
 call(['update-index','--chmod=-x','--stdin'],'\n'.join(r['path'] for r in rows).encode()+b'\n')
 executable=[r['path'] for r in rows if r['mode']==0o755]
 if executable:call(['update-index','--chmod=+x','--stdin'],'\n'.join(executable).encode()+b'\n')
 call(['commit','--quiet','--no-gpg-sign','--allow-empty','-m',SNAPSHOT_MESSAGE])
 sha=call(['rev-parse','HEAD']).decode().strip();need(bool(re.fullmatch('[a-f0-9]{40}',sha)))
 need(not call(['status','--porcelain','--untracked-files=all']).strip());verify_source(root,rows,allow_git=True)
 return sha
