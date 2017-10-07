const bls = require('bls-lib')
const dkg = require('./')

bls.onModuleInit(() => {
  // We are going to walk through Distributed Key Generation.
  // In DKG a group of members generate a "shared secert key" that none of them
  // know individal and public key. When a threshold amount of group members agree to sign on
  // the same message then then anyone can combine the signatures into a single
  // signature that can be verified against the groups public key
  //
  // The result of dkg be 1) each member will generate a secert key used to
  // sign messages for the group. 2) a group verification vector which contains
  // the groups public key as well as the the information need to derive any
  // of the members public key.
  //
  // Overview
  // 1) Each member will "setup" and generate a verification vector and secert
  // key contrubution share for every other member
  // 2) Each member post their verifcation vector publicly
  // 3) Each member sends their key contrubution share each other member
  // 4) When a member recieves a contrubution share it validates it against
  // the senders verifcation vector and saves it
  // 5) After members receive all thier contrubution shares they compute
  // their secret key for the group

  bls.init()
  // to setup a group first we need a set a threshold. The threshold is the
  // number of group participants need to create a valid siganture for the group
  const threshold = 4

  // each member in the group needs a unique ID. What the id is doesn't matter
  // but it does need to be imported into bls-lib as a secert key
  const members = [0, 1, 2, 3, 4, 5, 6].map(id => {
    const sk = bls.secretKey()
    bls.hashToSecretKey(sk, Buffer.from([id]))
    return {
      id: sk,
      recievedShares: []
    }
  })

  // this stores an array of verifcation vectors. One for each Member
  const vvecs = []
  // this stores an array of secertKey contrubutions. One for each member
  const skContributions = []

  // each member need to first create a one verification vector and a secert key
  // contrubution for every other member in the group (inculding itself!)
  members.forEach(id => {
    const {verificationVector, secretKeyContribution} = dkg.generateContribution(bls, members.map(m => m.id), threshold)
    // the verification vector should be posted publically so that everyone
    // in the group can see it
    vvecs.push(verificationVector)
    skContributions.push(secretKeyContribution)

    // Each secert sk contrubution is the encrypted an send to the member to
    // the member it is for.
    secretKeyContribution.forEach((sk, i) => {
      // when a group member receives its share, it verifys it against the
      // verification vector of the sender and then saves it
      const member = members[i]
      const verified = dkg.verifyContributionShare(bls, member.id, sk, verificationVector)
      if (!verified) {
        throw new Error('invalid share!')
      }
      member.recievedShares.push(sk)
    })
  })

  // now each members adds together all recieved secert key contrubutions shares to get a
  // single secertkey share for the group used for signing message for the group
  members.forEach((member, i) => {
    const sk = dkg.addContributionShares(bls, member.recievedShares)
    member.secretKeyShare = sk
  })

  // Now any one can add together the all verification vectors posted by the
  // members of the group to get a single verification vector of for the group
  const groupsVvec = dkg.addVerificationVectors(bls, vvecs)

  // the groups verifcation vector contains the groups public key. The groups
  // public key is the first element in the array
  const groupsPublicKey = groupsVvec[0]

  // now we can select any 4 members to sign on a message
  const message = 'hello world'
  const sigs = []
  const signersIds = []
  for (let i = 0; i < threshold; i++) {
    const sig = bls.signature()
    bls.sign(sig, members[i].secretKeyShare, message)
    sigs.push(sig)
    signersIds.push(members[i].id)
  }

  // then anyone can combine the signatures to get the groups signature
  // the resulting signature will also be the same no matter which members signed
  const groupsSig = bls.signature()
  bls.signatureRecover(groupsSig, sigs, signersIds)

  const verified = bls.verify(groupsSig, groupsPublicKey, message)
  console.log('is verified?', Boolean(verified))
  bls.free(groupsSig)

  // we can also use the groups verification vector to derive an of the members
  // public key
  const member = members[4]
  const pk1 = bls.publicKey()
  bls.publicKeyShare(pk1, groupsVvec, member.id)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, member.secretKeyShare)
  console.log('are the signatures equal?', Boolean(bls.publicKeyIsEqual(pk1, pk2)))

  // don't forget to clean up!
  bls.free(pk1)
  bls.free(pk2)
  bls.freeArray(groupsVvec)
  members.forEach(m => {
    bls.free(m.secretKeyShare)
    bls.free(m.id)
  })
})
