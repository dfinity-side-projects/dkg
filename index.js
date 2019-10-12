/**
 * generates a members contribution to the DKG
 * @param {Object} bls - an instance of [bls-wasm](https://github.com/herumi/bls-wasm)
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
    const sk = new bls.SecretKey()
    sk.setByCSPRNG()
    svec.push(sk)

    const pk = sk.getPublicKey()
    vvec.push(pk)
  }

  // generate key shares
  for (const id of ids) {
    const sk = new bls.SecretKey()
    sk.share(svec, id)
    skContribution.push(sk)
  }

  svec.forEach(s => s.clear())

  return {
    verificationVector: vvec,
    secretKeyContribution: skContribution
  }
}

/**
 * generates a members contribution to the DKG, ensuring the secret is null
 * @param {Object} bls - an instance of [bls-wasm](https://github.com/herumi/bls-wasm)
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
  const zeroSK = new bls.SecretKey()
  zeroSK.deserialize(zeroArray)
  svec.push(zeroSK)

  const zeroPK = zeroSK.getPublicKey()
  vvec.push(zeroPK)

  // generate a sk and vvec
  for (let i = 1; i < threshold; i++) {
    const sk = new bls.SecretKey()
    sk.setByCSPRNG()
    svec.push(sk)

    const pk = sk.getPublicKey()
    vvec.push(pk)
  }

  // generate key shares
  for (const id of ids) {
    const sk = new bls.SecretKey()
    sk.share(svec, id)
    skContribution.push(sk)
  }

  svec.forEach(s => s.clear())

  return {
    verificationVector: vvec,
    secretKeyContribution: skContribution
  }
}

/**
 * Adds secret key contribution together to produce a single secret key
 * @param {Array<Number>} secretKeyShares - an array of pointer to secret keys to add
 * @returns {Number} a pointer to the resulting secret key
 */
exports.addContributionShares = function (secretKeyShares) {
  const first = secretKeyShares.pop()
  secretKeyShares.forEach(sk => {
    first.add(sk)
    sk.clear()
  })
  return first
}

/**
 * Verifies a contribution share
 * @param {Object} bls - an instance of [bls-wasm](https://github.com/herumi/bls-wasm)
 * @param {Number} id - a pointer to the id of the member verifiing the contribution
 * @param {Number} contribution - a pointer to the secret key contribution
 * @param {Array<Number>} vvec - an array of pointers to public keys which is
 * the verification vector of the sender of the contribution
 * @returns {Boolean}
 */
exports.verifyContributionShare = function (bls, id, contribution, vvec) {
  const pk1 = new bls.PublicKey()
  pk1.share(vvec, id)

  const pk2 = contribution.getPublicKey()

  const isEqual = pk1.isEqual(pk2)

  pk1.clear()
  pk2.clear()

  return Boolean(isEqual)
}

/**
 * Adds an array of verification vectors together to produce the groups verification vector
 * @param {Array<Array<Number>>} vvecs - an array containing all the groups verifciation vectors
 */
exports.addVerificationVectors = function (vvecs) {
  const groupsVvec = []
  vvecs.forEach(vvec => {
    vvec.forEach((pk2, i) => {
      let pk1 = groupsVvec[i]
      if (!pk1) {
        groupsVvec[i] = pk2
      } else {
        pk1.add(pk2)
        pk2.clear()
      }
    })
  })
  return groupsVvec
}
