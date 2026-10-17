import pathlib,subprocess,resource
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
p=pathlib.Path('/private/tmp/intmax3-wrapper-config-review-20261016-hasher')
lines=[]
for case in ['valid_zero','valid_max','json_wrong_type','json_nondecimal','json_modulus','binary_noncanonical']:
 r=subprocess.run([str(p/'probe'),case],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 lines += ['CASE '+case,'EXIT '+str(r.returncode),'STDOUT '+r.stdout.strip(),'STDERR '+r.stderr.strip(),'']
text='\n'.join(lines)
(p/'probe-results.log').write_text(text)
print(text)
