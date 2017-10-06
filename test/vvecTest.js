const bls = require('bls-lib')
const threshold = 4

bls.onModuleInit(() => {
  bls.init()

  // create the ids
  const ids = [0, 1, 2, 3, 4, 5, 6].map(id => {
    const sk = bls.secretKey()
    bls.hashToSecretKey(sk, Buffer.from([id]))
    return sk
  })

  // this stores an array of verifcation vectors. One for each ID
  const vvecs = []
  // this stores an array of secertKey contrubutions. One for each ID
  const skContributions = []

  // setup
  ids.forEach(id => {
    // this id's verification vector
    const vvec = []
    // this id's secert keys
    const svec = []
    // this id's sk contrubutions shares
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

    skContributions.push(skContribution)
    vvecs.push(vvec)
  })

  // now each id adds together all sk contrubutions to get thier sk for the group
  const groupsSks = []
  skContributions.forEach(skvec => {
    skvec.forEach((sk2, i) => {
      let sk1 = groupsSks[i]
      if (!sk1) {
        // we are reusing a pointer here, but since skContributions isn't used
        // after this it should be fine
        groupsSks[i] = sk2
      } else {
        bls.secretKeyAdd(sk1, sk2)
      }
    })
  })

  // add together the all vvecs
  const groupsVvec = []
  vvecs.forEach(vvec => {
    vvec.forEach((pk2, i) => {
      let pk1 = groupsVvec[i]
      if (!pk1) {
        groupsVvec[i] = pk2
      } else {
        bls.publicKeyAdd(pk1, pk2)
      }
    })
  })

  // derive the public key for each id from there secert key share
  const groupsPks = []
  ids.forEach((id, i) => {
    const pk = bls.publicKey()
    bls.publicKeyShare(pk, groupsVvec, id)
    groupsPks.push(pk)

    const sk = groupsSks[i]
    const pk2 = bls.publicKey()
    bls.getPublicKey(pk2, sk)
    const equal = bls.publicKeyIsEqual(pk, pk2)
    console.log(equal)
  })

  const groupsPk = bls.publicKey()
  bls.publicKeyRecover(groupsPk, groupsPks.slice(0, threshold), ids.slice(0, threshold))
  const equal = bls.publicKeyIsEqual(groupsPk, groupsVvec[0])
  console.log(equal)
})
