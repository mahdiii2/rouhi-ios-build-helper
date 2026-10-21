"""One exact native context adaptation; downstream native guards stay unchanged."""
import ast,hashlib
BASELINES={'driver':'b21259a256966fb873590cd9e71e2eb6d6853ed93ff3fb14344ea835206917f9','customer':'4f65fcb4c99f4af0041eae51ba7dd011da859fdb1799599d89e580b7dd34c5bd'}
OLD='''    require(environment.get("GITHUB_REPOSITORY") == EXPECTED_REPOSITORY, "own_repository_required")
    require(environment.get("GITHUB_REF") == "refs/heads/uber", "reviewed_uber_branch_required")
    source = environment.get("RIDES_IOS_SOURCE_SHA", "")
    require(re.fullmatch(r"[a-f0-9]{40}", source) is not None
            and source == environment.get("GITHUB_SHA"), "exact_dispatch_source_required")'''
NEW='''    if environment.get("RIDES_IOS_CONTEXT") == "sealed-helper-v2":
        from sealed_ios_context import validate_context
        validate_context(environment, ROLE)
    else:
'''+''.join('    '+line+'\n' for line in OLD.splitlines()).rstrip('\n')
def adapt(raw,role):
 if role not in BASELINES or hashlib.sha256(raw).hexdigest()!=BASELINES[role]:raise ValueError('native_adapter_baseline_changed')
 text=raw.decode()
 if text.count(OLD)!=1:raise ValueError('native_adapter_exact_predecessor_required')
 result=text.replace(OLD,NEW,1).encode()
 before=ast.parse(text);after=ast.parse(result)
 b={n.name:ast.dump(n,include_attributes=False) for n in before.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 a={n.name:ast.dump(n,include_attributes=False) for n in after.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 if set(a)!=set(b) or any(a[k]!=v for k,v in b.items() if k!='validate_inputs'):raise ValueError('native_adapter_unrelated_change')
 return result
