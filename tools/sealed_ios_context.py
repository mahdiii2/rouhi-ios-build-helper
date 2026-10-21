"""Bind actual public execution identity separately from the private source snapshot."""
import re
def require(v,code):
 if not v:raise ValueError(code)
def validate_context(e,role):
 require(role in {'customer','driver'},'sealed_role_invalid')
 require(e.get('GITHUB_REPOSITORY')=='mahdiii2/rouhi-ios-build-helper' and e.get('GITHUB_REPOSITORY_OWNER')=='mahdiii2','sealed_helper_repository_required')
 require(e.get('GITHUB_ACTOR')==e.get('GITHUB_TRIGGERING_ACTOR')=='mahdiii2','sealed_owner_required')
 require(e.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and e.get('GITHUB_REF')=='refs/heads/main','sealed_manual_main_required')
 helper=e.get('SEALED_REVIEWED_HELPER_SHA','');source=e.get('RIDES_IOS_SOURCE_SHA','')
 require(bool(re.fullmatch('[a-f0-9]{40}',helper)) and helper==e.get('GITHUB_SHA'),'sealed_actual_helper_commit_required')
 require(bool(re.fullmatch('[a-f0-9]{40}',source)) and source==e.get('SEALED_REVIEWED_SOURCE_SHA'),'sealed_private_snapshot_commit_required')
 require(bool(re.fullmatch('[a-f0-9]{64}',e.get('SEALED_REVIEWED_MANIFEST_SHA256',''))),'sealed_private_closure_required')
 require(e.get('SEALED_REVIEWED_ROLE')==role and e.get('RIDES_IOS_UPLOAD')=='false','sealed_role_and_no_upload_required')
 require(e.get('ASC_APP_ID')=={'customer':'6821814203','driver':'6821815632'}[role],'sealed_exact_apple_app_required')
