const tape = require('tape')
const bls = require('bls-wasm')
const threshold = 4
const dkg = require('../')

bls.init().then(() => {
  tape('dkg', t => {
    // create the ids
    const ids = [0, 1, 2, 3, 4, 5, 6].map(id => {
      const sk = new bls.SecretKey()
      sk.setHashOf(Buffer.from([id]))
      return sk
    })

    // this stores an array of verifcation vectors. One for each ID
    const vvecs = []
    // this stores an array of secertKey contrubutions. One for each ID
    const skContributions = []

    // setup
    ids.forEach(id => {
      const {verificationVector, secretKeyContribution} = dkg.generateContribution(bls, ids, threshold)
      skContributions.push(secretKeyContribution)
      vvecs.push(verificationVector)
    })

    // verify each share
    ids.forEach((id, i) => {
      skContributions.forEach((skc, q) => {
        const result = dkg.verifyContributionShare(bls, id, skc[i], vvecs[q])
        t.true(result, 'should verify contribution share')
      })
    })

    // now each id adds together all sk contrubutions to get thier sk for the group
    const groupsSks = []
    ids.forEach((id, i) => {
      const shares = []
      skContributions.forEach(skvec => {
        shares.push(skvec[i])
      })
      const sk = dkg.addContributionShares(shares)
      groupsSks[i] = sk
    })

    // add together the all vvecs
    const groupsVvec = dkg.addVerificationVectors(vvecs)

    // derive the public key for each id from there secert key share
    const groupsPks = []
    ids.forEach((id, i) => {
      const pk = new bls.PublicKey()
      pk.share(groupsVvec, id)
      groupsPks.push(pk)

      const sk = groupsSks[i]
      const pk2 = sk.getPublicKey()
      const equal = pk.isEqual(pk2)
      t.true(equal, 'public key derived from groups vvec should equal pk from secert share')
    })

    const groupsPk = new bls.PublicKey()
    groupsPk.recover(groupsPks.slice(0, threshold), ids.slice(0, threshold))
    const equal = groupsPk.isEqual(groupsVvec[0])
    t.true(equal, 'groups public key should equal pk derived from pk shares')
    t.end()
  })
})
