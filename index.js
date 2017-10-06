exports.setup = function (bls, ids, threshold) {
  const verificationVector = []
  const secretKeyShares = []
  let secretKeyVector = []

  // import the ids
  ids = ids.map(id => {
    const idp = bls.secretKey()
    bls.hashToSecretKey(idp, id)
    return {
      id: id,
      pointer: idp
    }
  })

  // generate our polynomial
  for (let i = 0; i < threshold; i++) {
    const sk = bls.secretKey()
    bls.secretKeySetByCSPRNG(sk)
    secretKeyVector.push(sk)

    const pk = bls.publicKey()
    bls.getPublicKey(pk, sk)

    const pkArray = bls.publicKeySerialize(pk)
    verificationVector.push(pkArray)
    bls.free(pk)
  }

  // generate a share for each member in the group
  for (const id of ids) {
    const sk = bls.secretKey()
    bls.secretKeyShare(sk, secretKeyVector, id.pointer)
    secretKeyShares.push({
      secretKey: bls.secretKeySerialize(sk),
      to: id.id
    })
    bls.free(id.pointer)
    bls.free(sk)
  }

  secretKeyVector = secretKeyVector.map(sk => {
    const skArray = bls.secretKeySerialize(sk)
    // clean up
    bls.free(sk)
    return skArray
  })

  return {
    // secretKeyVector: secretKeyVector,
    verificationVector: verificationVector,
    secretKeyShares: secretKeyShares
  }
}

exports.verifyShare = function (bls, id, share, vvec) {
  // import the id
  const idptr = bls.secretKey()
  bls.hashToSecretKey(idptr, id)

  const sk = bls.secretKey()
  bls.secretKeyDeserialize(sk, share)

  // import the vvec
  vvec = vvec.map(pk => {
    const pointer = bls.publicKey()
    bls.publicKeyDeserialize(pointer, pk)
    return pointer
  })

  const pk1 = bls.publicKey()
  bls.publicKeyShare(pk1, vvec, idptr)
  vvec.forEach(pk => bls.free(pk))
  bls.free(idptr)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, sk)
  bls.free(sk)

  const isEqual = bls.publicKeyIsEqual(pk1, pk2)
  bls.free(pk1)
  bls.free(pk2)

  return Boolean(isEqual)
}

exports.addShares = function (bls, secretKeyShares) {
  const secretKey = secretKeyShares.slice(0).pop().secretKey

  const sk = bls.secretKey()
  bls.secretKeyDeserialize(sk, secretKey)

  secretKeyShares.forEach(share => {
    const ssk = bls.secretKey()
    bls.secretKeyDeserialize(sk, share.secretKey)
    bls.secretKeyAdd(sk, ssk)
    bls.free(ssk)
  })

  const pk = bls.publicKey()
  bls.getPublicKey(pk, sk)
  const secretKeyArray = bls.secretKeySerialize(sk)
  bls.free(sk)
  const publicKeyArray = bls.publicKeySerialize(pk)
  bls.free(pk)

  return {
    secretKey: secretKeyArray,
    publicKey: publicKeyArray
  }
}

exports.publicKeyRecover = function (bls, publicKeyShares, threshold) {
  publicKeyShares = publicKeyShares.slice(0, threshold)
  const pks = publicKeyShares.map(s => {
    const pk = bls.publicKey()
    bls.publicKeyDeserialize(pk, s.publicKey)
    return pk
  })
  const ids = publicKeyShares.map(s => {
    const id = bls.secretKey()
    bls.hashToSecretKey(id, s.id)
    return id
  })
  const pk = bls.publicKey()

  bls.publicKeyRecover(pk, pks, ids)
  ids.forEach(id => bls.free(id))
  pks.forEach(p => bls.free(p))
  return pk
}

exports.secretKeyRecover = function (bls, publicKeyShares, threshold) {
  publicKeyShares = publicKeyShares.slice(0, threshold)
  const pks = publicKeyShares.map(s => {
    const pk = bls.secretKey()
    bls.secretKeyDeserialize(pk, s.secretKey)
    return pk
  })
  const ids = publicKeyShares.map(s => {
    const id = bls.secretKey()
    bls.hashToSecretKey(id, s.id)
    return id
  })
  const sk = bls.secretKey()
  const pk = bls.publicKey()

  bls.secretKeyRecover(sk, pks, ids)
  bls.getPublicKey(pk, sk)

  ids.forEach(id => bls.free(id))
  pks.forEach(p => bls.free(p))
  return pk
}

exports.getGroupsPubKey = function (bls, vvecs) {
  // import the vvec
  vvecs = vvecs.slice(0)

  const groupsVvec = []
  vvecs.forEach(vvec => {
    vvec.forEach((pk2s, i) => {
      const pk2 = bls.publicKey()
      bls.publicKeyDeserialize(pk2, pk2s)
      let pk1 = groupsVvec[i]
      if (!pk1) {
        groupsVvec[i] = pk2
      } else {
        bls.publicKeyAdd(pk1, pk2)
      }
    })
  })

  const result = bls.publicKeySerialize(groupsVvec[0])
  console.log(Buffer.from(result).toString('hex'))
}
