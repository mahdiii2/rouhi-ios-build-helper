"""Streaming authenticated build payloads. This format is separate from diagnostics."""
import base64,hashlib,json,os,struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

MAGIC=b'ROUHI-SEALED-IOS-2\n';MAX_HEADER=16384;CHUNK=1024*1024;LABEL=b'rouhi-sealed-ios-output-v2'
def need(v):
 if not v:raise ValueError('sealed_payload_invalid')
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def unique(pairs):
 d={}
 for k,v in pairs:need(k not in d);d[k]=v
 return d
def digest_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(CHUNK),b''):h.update(b)
 return h.hexdigest()
def json_bytes(b):return json.loads(b,object_pairs_hook=unique,parse_constant=lambda _:need(False))
def _private_open(p):
 return os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb')
def _seal(src,dst,key,header,maximum):
 need(type(key) is bytes and len(key)==32 and 0<Path(src).stat().st_size<=maximum)
 raw=canonical(header);need(len(raw)<=MAX_HEADER)
 enc=Cipher(algorithms.AES(key),modes.GCM(base64.b64decode(header['nonce'],validate=True))).encryptor();enc.authenticate_additional_data(raw)
 created=False
 try:
  with Path(src).open('rb') as inp:
   out=_private_open(dst);created=True
   with out:
    out.write(MAGIC+struct.pack('>I',len(raw))+raw);total=0
    for b in iter(lambda:inp.read(CHUNK),b''):
     total+=len(b);need(total<=maximum);out.write(enc.update(b))
    out.write(enc.finalize());out.write(enc.tag);out.flush();os.fsync(out.fileno())
 except BaseException:
  if created:Path(dst).unlink(missing_ok=True)
  raise
 return {'sha256':digest_file(dst),'bytes':Path(dst).stat().st_size}
def seal_input(src,dst,key,context,maximum):
 return _seal(src,dst,key,{'schema':2,'purpose':'input','algorithm':'AES-256-GCM','context':context,'nonce':base64.b64encode(os.urandom(12)).decode()},maximum)
def seal_output(src,dst,public_pem,expected_public_sha,context,maximum):
 need(hashlib.sha256(public_pem).hexdigest()==expected_public_sha)
 pub=serialization.load_pem_public_key(public_pem);need(isinstance(pub,rsa.RSAPublicKey) and pub.key_size==3072)
 key=os.urandom(32);wrapped=pub.encrypt(key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=LABEL))
 return _seal(src,dst,key,{'schema':2,'purpose':'output','algorithm':'AES-256-GCM+RSA-OAEP-SHA256','context':context,'recipient_sha256':expected_public_sha,'wrapped_key':base64.b64encode(wrapped).decode(),'nonce':base64.b64encode(os.urandom(12)).decode()},maximum)
def open_payload(src,dst,*,context,maximum,key=None,private_pem=None):
 """Authenticate fully before any extraction. Remove unauthenticated plaintext."""
 src=Path(src);need(src.stat().st_size<=maximum+MAX_HEADER+len(MAGIC)+20)
 created=False
 try:
  with src.open('rb') as inp:
   need(inp.read(len(MAGIC))==MAGIC);length=struct.unpack('>I',inp.read(4))[0];need(0<length<=MAX_HEADER)
   raw=inp.read(length);h=json_bytes(raw);need(canonical(h)==raw and h['schema']==2 and h['context']==context)
   if key is not None:
    need(set(h)=={'schema','purpose','algorithm','context','nonce'} and h['purpose']=='input' and h['algorithm']=='AES-256-GCM')
   else:
    need(set(h)=={'schema','purpose','algorithm','context','nonce','recipient_sha256','wrapped_key'} and h['purpose']=='output' and h['algorithm']=='AES-256-GCM+RSA-OAEP-SHA256')
    private=serialization.load_pem_private_key(private_pem,password=None);need(isinstance(private,rsa.RSAPrivateKey) and private.key_size==3072)
    pub=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);need(hashlib.sha256(pub).hexdigest()==h['recipient_sha256'])
    key=private.decrypt(base64.b64decode(h['wrapped_key'],validate=True),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=LABEL))
   nonce=base64.b64decode(h['nonce'],validate=True);need(len(nonce)==12 and type(key) is bytes and len(key)==32)
   start=inp.tell();count=src.stat().st_size-start-16;need(0<count<=maximum)
   inp.seek(-16,2);tag=inp.read(16);inp.seek(start)
   dec=Cipher(algorithms.AES(key),modes.GCM(nonce,tag)).decryptor();dec.authenticate_additional_data(raw)
   out=_private_open(dst);created=True
   with out:
    left=count
    while left:
     b=inp.read(min(CHUNK,left));need(bool(b));left-=len(b);out.write(dec.update(b))
    out.write(dec.finalize());out.flush();os.fsync(out.fileno())
 except BaseException:
  if created:Path(dst).unlink(missing_ok=True)
  raise
 return {'sha256':digest_file(dst),'bytes':Path(dst).stat().st_size}
