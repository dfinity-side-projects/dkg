/**
 * generates a members contribution to the DKG
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Array<Number>} ids - an array of pointers containing the ids of the members of the groups
 * @param {Number} threshold - the threshold number of members needed to sign on a message to
 * produce the groups signature
 * @returns {Object} the object contains `verificationVector` which is an array of public key pointers
 * and `secretKeyContribution` which is an array of secret key pointers
 */
exports.generateContribution = function (bls, ids, threshold) {
  // this id's verification vector
  const vvec = []
  // this id's secret keys
  const svec = []
  // this id's sk contributions shares
  const skContribution = []
  // generate a sk and vvec
  for (let i = 0; i < threshold; i++) {
    const sk = bls.secretKey()
    bls.secretKeySetByCSPRNG(sk)
    svec.push(sk)

    const pk = bls.publicKey()
    bls.getPublicKey(pk, sk)
    vvec.push(pk)
  }

  // generate key shares
  for (const id of ids) {
    const sk = bls.secretKey()
    bls.secretKeyShare(sk, svec, id)
    skContribution.push(sk)
  }

  svec.forEach(s => bls.free(s))

  return {
    verificationVector: vvec,
    secretKeyContribution: skContribution
  }
}

/**
 * generates a members contribution to the DKG, ensuring the secret is null
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Array<Number>} ids - an array of pointers containing the ids of the members of the groups
 * @param {Number} threshold - the threshold number of members needed to sign on a message to
 * produce the groups signature
 * @returns {Object} the object contains `verificationVector` which is an array of public key pointers
 * and `secretKeyContribution` which is an array of secret key pointers
 */
exports.generateZeroContribution = function (bls, ids, threshold) {
  // this id's verification vector
  const vvec = []
  // this id's secret keys
  const svec = []
  // this id's sk contributions shares
  const skContribution = []

  const zeroArray = Buffer.alloc(32)
  const zeroSK = bls.secretKeyImport(zeroArray)
  svec.push(zeroSK)

  const zeroPK = bls.publicKey()
  bls.getPublicKey(zeroPK, zeroSK)
  vvec.push(zeroPK)

  // generate a sk and vvec
  for (let i = 1; i < threshold; i++) {
    const sk = bls.secretKey()
    bls.secretKeySetByCSPRNG(sk)
    svec.push(sk)

    const pk = bls.publicKey()
    bls.getPublicKey(pk, sk)
    vvec.push(pk)
  }

  // generate key shares
  for (const id of ids) {
    const sk = bls.secretKey()
    bls.secretKeyShare(sk, svec, id)
    skContribution.push(sk)
  }

  svec.forEach(s => bls.free(s))

  return {
    verificationVector: vvec,
    secretKeyContribution: skContribution
  }
}

/**
 * Adds secret key contribution together to produce a single secret key
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Array<Number>} secretKeyShares - an array of pointer to secret keys to add
 * @returns {Number} a pointer to the resulting secret key
 */
exports.addContributionShares = function (bls, secretKeyShares) {
  const first = secretKeyShares.pop()
  secretKeyShares.forEach(sk => {
    bls.secretKeyAdd(first, sk)
    bls.free(sk)
  })
  return first
}

/**
 * Verifies a contribution share
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Number} id - a pointer to the id of the member verifiing the contribution
 * @param {Number} contribution - a pointer to the secret key contribution
 * @param {Array<Number>} vvec - an array of pointers to public keys which is
 * the verification vector of the sender of the contribution
 * @returns {Boolean}
 */
exports.verifyContributionShare = function (bls, id, contribution, vvec) {
  const pk1 = bls.publicKey()
  bls.publicKeyShare(pk1, vvec, id)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, contribution)

  const isEqual = bls.publicKeyIsEqual(pk1, pk2)

  bls.free(pk1)
  bls.free(pk2)

  return Boolean(isEqual)
}

/**
 * Adds an array of verification vectors together to produce the groups verification vector
 * @param {Object} bls - an instance of [bls-lib](https://github.com/wanderer/bls-lib)
 * @param {Array<Array<Number>>} vvecs - an array containing all the groups verifciation vectors
 */
exports.addVerificationVectors = function (bls, vvecs) {
  const groupsVvec = []
  vvecs.forEach(vvec => {
    vvec.forEach((pk2, i) => {
      let pk1 = groupsVvec[i]
      if (!pk1) {
        groupsVvec[i] = pk2
      } else {
        bls.publicKeyAdd(pk1, pk2)
        bls.free(pk2)
      }
    })
  })
  return groupsVvec
}
