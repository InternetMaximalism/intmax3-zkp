from pathlib import Path
import re,json,hashlib,math,itertools
base=Path(__file__).resolve().parent / 'reference'
root=Path('/Users/andropov/repos/intmax3-zkp')
go=(base/'constants.go').read_text(); rust=(root/'src/wrapper_config/poseidon_bn128_constants.rs').read_text()
q=21888242871839275222246405745257275088548364400416034343698204186575808495617

def go_table(name):
    marker=re.search(r'\n\s*'+name+r':\s*(?:\[\])+string',go)
    assert marker,name
    start=go.index('{',marker.end()); level=0
    for end in range(start,len(go)):
        if go[end]=='{': level+=1
        if go[end]=='}':
            level-=1
            if level==0: break
    literal=go[start:end+1].replace('{','[').replace('}',']')
    literal=re.sub(r',\s*\]',']',literal)
    raw=json.loads(literal)
    def conv(x): return [conv(v) for v in x] if isinstance(x,list) else int(x,16)
    return conv(raw)[2] # t=4 uses index t-2

def rust_vector(name,n):
    matches=re.findall(name+r'\[(\d+)\]\s*=\s*Fr::from_str_vartime\(\s*"(\d+)"',rust)
    assert len(matches)==n and {int(i) for i,v in matches}==set(range(n)),name
    return [int(dict(matches)[str(i)]) for i in range(n)]

def rust_matrix(name):
    matches=re.findall(name+r'\[(\d+)\]\[(\d+)\]\s*=\s*Fr::from_str_vartime\(\s*"(\d+)"',rust)
    assert len(matches)==16 and {(int(i),int(j)) for i,j,v in matches}==set(itertools.product(range(4),repeat=2)),name
    data={(int(i),int(j)):int(v) for i,j,v in matches}
    return [[data[i,j] for j in range(4)] for i in range(4)]

actual={'C':rust_vector('c_constants',88),'S':rust_vector('s_constants',392),'M':rust_matrix('m_matrix'),'P':rust_matrix('p_matrix')}
for name,vals in actual.items():
    assert vals==go_table(name),name+' differs'
    flat=list(itertools.chain.from_iterable(vals)) if name in ['M','P'] else vals
    assert all(0<=v<q for v in flat)
    print('PASS reference equality and canonical field range:',name,'entries=',len(flat))

def det(a):
    a=[row[:] for row in a]; r=1
    for k in range(len(a)):
        pivot=next((i for i in range(k,len(a)) if a[i][k]%q),None)
        if pivot is None:return 0
        if pivot!=k:a[k],a[pivot]=a[pivot],a[k]; r=-r
        p=a[k][k]%q; r=r*p%q; inv=pow(p,q-2,q)
        for i in range(k+1,len(a)):
            factor=a[i][k]*inv%q
            for j in range(k+1,len(a)):a[i][j]=(a[i][j]-factor*a[k][j])%q
    return r%q

minors=0
for k in range(1,5):
    for rows in itertools.combinations(range(4),k):
        for cols in itertools.combinations(range(4),k):
            assert det([[actual['M'][i][j] for j in cols] for i in rows])!=0
            minors+=1
assert det(actual['P'])!=0
for i in range(56):
    s=actual['S'][i*7:(i+1)*7]
    assert (s[0]-sum(s[j]*s[3+j] for j in range(1,4)))%q!=0
assert math.gcd(5,q-1)==1
print('PASS MDS:',minors,'square minors of M nonzero; P invertible; all56 sparse matrices invertible; gcd(5,r-1)=1')
# Source inventory for reproducibility, not a claim of a security proof.
inventory=[]
for path in [base/'poseidon.go',base/'constants.go',base/'element.go',root/'src/wrapper_config/poseidon_bn128.rs',root/'src/wrapper_config/poseidon_bn128_constants.rs',root/'src/wrapper_config/utils.rs']:
    inventory.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
(base/'source-hashes.json').write_text(json.dumps(inventory,indent=2)+'\n')
