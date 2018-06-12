const bls = require('bls-lib')
const dkg = require('./')

bls.onModuleInit(() => {
  // We are going to walk through Distributed Key Generation.
  // In DKG a group of members generate a "shared secret key" that none of them
  // know individal and public key. When a threshold amount of group members agree to sign on
  // the same message then then anyone can combine the signatures into a single
  // signature that can be verified against the groups public key
  //
  // The result of dkg be 1) each member will generate a secret key used to
  // sign messages for the group. 2) a group verification vector which contains
  // the groups public key as well as the the information need to derive any
  // of the members public key.
  //
  // Overview
  // 1) Each member will "setup" and generate a verification vector and secret
  // key contrubution share for every other member
  // 2) Each member post their verifcation vector publicly
  // 3) Each member sends their key contrubution share each other member
  // 4) When a member recieves a contrubution share it validates it against
  // the senders verifcation vector and saves it
  // 5) After members receive all thier contribution shares they compute
  // their secret key for the group

  bls.init()

  // to setup a group first we need a set a threshold. The threshold is the
  // number of group participants need to create a valid siganture for the group
  const threshold = 4
  // each member in the group needs a unique ID. What the id is doesn't matter
  // but it does need to be imported into bls-lib as a secret key
  const members = [10314, 30911, 25411, 8608, 31524, 15441, 23399].map(id => {
    const sk = bls.secretKey()
    bls.hashToSecretKey(sk, Buffer.from([id]))
    return {
      id: sk,
      recievedShares: []
    }
  })

  console.log('Beginning the secret instantiation round...')

  // this stores an array of verifcation vectors. One for each Member
  const vvecs = []

  // each member need to first create a verification vector and a secret key
  // contribution for every other member in the group (including itself!)
  members.forEach(id => {
    const {verificationVector, secretKeyContribution} = dkg.generateContribution(bls, members.map(m => m.id), threshold)
    // the verification vector should be posted publically so that everyone
    // in the group can see it
    vvecs.push(verificationVector)

    // Each secret sk contribution is then encrypted and sent to the member it is for.
    secretKeyContribution.forEach((sk, i) => {
      // when a group member receives its share, it verifies it against the
      // verification vector of the sender and then saves it
      const member = members[i]
      const verified = dkg.verifyContributionShare(bls, member.id, sk, verificationVector)
      if (!verified) {
        throw new Error('invalid share!')
      }
      member.recievedShares.push(sk)
    })
  })

  // now each members adds together all received secret key contributions shares to get a
  // single secretkey share for the group used for signing message for the group
  members.forEach((member, i) => {
    const sk = dkg.addContributionShares(bls, member.recievedShares)
    member.secretKeyShare = sk
  })
  console.log('-> secret shares have been generated')

  // Now any one can add together the all verification vectors posted by the
  // members of the group to get a single verification vector of for the group
  const groupsVvec = dkg.addVerificationVectors(bls, vvecs)
  console.log('-> verification vector computed')

  // the groups verifcation vector contains the groups public key. The group's
  // public key is the first element in the array
  const groupsPublicKey = groupsVvec[0]

  const pubArray = bls.publicKeyExport(groupsPublicKey)
  console.log('-> group public key : ', Buffer.from(pubArray).toString('hex'))

  console.log('-> testing signature')
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

  const sigArray = bls.signatureExport(groupsSig)
  const sigBuf = Buffer.from(sigArray)
  console.log('->    sigtest result : ', sigBuf.toString('hex'))

  var verified = bls.verify(groupsSig, groupsPublicKey, message)
  console.log('->    verified ?', Boolean(verified))
  bls.free(groupsSig)

  console.log('-> testing individual public key derivation')
  // we can also use the groups verification vector to derive any of the members
  // public key
  const member = members[4]
  const pk1 = bls.publicKey()
  bls.publicKeyShare(pk1, groupsVvec, member.id)

  const pk2 = bls.publicKey()
  bls.getPublicKey(pk2, member.secretKeyShare)
  console.log('->    are the public keys equal?', Boolean(bls.publicKeyIsEqual(pk1, pk2)))

  console.log('\nBeginning the share renewal round...')

  const newVvecs = [groupsVvec]

  console.log('-> member shares array reinitialized')
  members.forEach(member => {
    member.recievedShares.length = 0
    member.recievedShares.push(member.secretKeyShare)
  })

  console.log('-> running null-secret contribution generator')
  // the process is very similar, only `generateZeroContribution` works with a null secret
  members.forEach(id => {
    const {verificationVector, secretKeyContribution} = dkg.generateZeroContribution(bls, members.map(m => m.id), threshold)
    // the verification vector should be posted publically so that everyone
    // in the group can see it
    newVvecs.push(verificationVector)

    // Each secret key contribution is then encrypted and sent to the member it is for.
    secretKeyContribution.forEach((sk, i) => {
      // when a group member receives its share, it verifies it against the
      // verification vector of the sender and then saves it
      const member = members[i]
      const verified = dkg.verifyContributionShare(bls, member.id, sk, verificationVector)
      if (!verified) {
        throw new Error('invalid share!')
      }
      member.recievedShares.push(sk)
    })
  })

  // now each members adds together all received secret key contributions shares to get a
  // single secretkey share for the group used for signing message for the group
  members.forEach((member, i) => {
    const sk = dkg.addContributionShares(bls, member.recievedShares)
    member.secretKeyShare = sk
  })
  console.log('-> new secret shares have been generated')

  // Now any one can add together the all verification vectors posted by the
  // members of the group to get a single verification vector of for the group
  const newGroupsVvec = dkg.addVerificationVectors(bls, newVvecs)
  console.log('-> verification vector computed')

  // the groups verifcation vector contains the groups public key. The group's
  // public key is the first element in the array
  const newGroupsPublicKey = newGroupsVvec[0]

  verified = (bls.publicKeyIsEqual(newGroupsPublicKey, groupsPublicKey))
  console.log('-> public key should not have changed :', (verified ? 'success' : 'failure'))

  console.log('-> testing signature using new shares')
  // now we can select any 4 members to sign on a message
  sigs.length = 0
  signersIds.length = 0
  for (let i = 0; i < threshold; i++) {
    const sig = bls.signature()
    bls.sign(sig, members[i].secretKeyShare, message)
    sigs.push(sig)
    signersIds.push(members[i].id)
  }

  // then anyone can combine the signatures to get the groups signature
  // the resulting signature will also be the same no matter which members signed
  const groupsNewSig = bls.signature()
  bls.signatureRecover(groupsNewSig, sigs, signersIds)

  const newSigArray = bls.signatureExport(groupsNewSig)
  const newSigBuf = Buffer.from(newSigArray)
  console.log('->    sigtest result : ', newSigBuf.toString('hex'))
  console.log('->    signature comparison :', ((newSigBuf.equals(sigBuf)) ? 'success' : 'failure'))

  verified = bls.verify(groupsNewSig, groupsPublicKey, message)
  console.log('->    verified ?', Boolean(verified))
  bls.free(groupsNewSig)

  // don't forget to clean up!
  bls.free(pk1)
  bls.free(pk2)
  bls.freeArray(groupsVvec)
  bls.freeArray(newGroupsVvec)
  members.forEach(m => {
    bls.free(m.secretKeyShare)
    bls.free(m.id)
  })
})
