# Makes merkle-vectors.json: python3 merkle-vectors.py merkle-vectors.json (Python 3 standard library only).
# Independent RFC 6962 section 2.1 Merkle tree: the definitions MTH, PATH and PROOF, written from the RFC text.
import hashlib, json, sys
def H(b): return hashlib.sha256(b).digest()
def leaf(d): return H(b"\x00"+d)
def node(l,r): return H(b"\x01"+l+r)
def k_of(n):
    k=1
    while k*2<n: k*=2
    return k
def mth(D):
    n=len(D)
    if n==0: return H(b"")
    if n==1: return leaf(D[0])
    k=k_of(n)
    return node(mth(D[:k]),mth(D[k:]))
def path(m,D):
    n=len(D)
    if n==1: return []
    k=k_of(n)
    if m<k: return path(m,D[:k])+[mth(D[k:])]
    return path(m-k,D[k:])+[mth(D[:k])]
def subproof(m,D,b):
    n=len(D)
    if m==n: return [] if b else [mth(D)]
    k=k_of(n)
    if m<=k: return subproof(m,D[:k],b)+[mth(D[k:])]
    return subproof(m-k,D[k:],False)+[mth(D[:k])]
def proof(m,D):
    return subproof(m,D,True)
leaves=[bytes.fromhex(x) for x in ["","00","10","2021","3031","40414243","5051525354555657","606162636465666768696a6b6c6d6e6f"]]
leaves+= [b"leaf %d"%i for i in range(8,13)]
CT=["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d","fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125","aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77","d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7","4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4","76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef","ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c","5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
for i,c in enumerate(CT): assert mth(leaves[:i+1]).hex()==c, i
N=len(leaves)
out={
 "about":"RFC 6962 section 2.1 Merkle tree vectors for REQ-AUDIT-005 and REQ-AUDIT-024. The first eight leaves and the roots of their prefixes are the Certificate Transparency reference tree (google/certificate-transparency, merkle_tree_test); every other value is computed from the RFC 6962 definitions MTH, PATH and PROOF by an independent program that shares no code with the product. The Go and Rust kits both read this file.",
 "leaves":[l.hex() for l in leaves],
 "roots":[mth(leaves[:n]).hex() for n in range(0,N+1)],
 "inclusion":[{"size":n,"index":i,"path":[x.hex() for x in path(i,leaves[:n])]} for n in range(1,N+1) for i in range(n)],
 "consistency":[{"old":m,"new":n,"path":[x.hex() for x in proof(m,leaves[:n])]} for n in range(1,N+1) for m in range(1,n+1)],
}
json.dump(out,open(sys.argv[1],"w"),indent=1)
