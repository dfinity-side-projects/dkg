const bls = require('bls-lib')
const shuffle = require('array-shuffle')

bls.onModuleInit(() => {
  bls.init()
  const numOfPlayers = 5
  const threshold = 3

  const secretKeyShares = Array(numOfPlayers)
  const publicKeys = []
  const ids = []
  const verificationVecs = []

  // generate ids
  for (let i = 0; i < numOfPlayers; i++) {
    const id = bls.secretKey()
    bls.secretKeySetByCSPRNG(id)
    ids[i] = id
    secretKeyShares[i] = []
  }

  // set up master key share
  for (let i = 0; i < numOfPlayers; i++) {
    const secretKeyVec = []
    const verVec = []
    for (let i = 0; i < threshold; i++) {
      const sk = bls.secretKey()
      bls.secretKeySetByCSPRNG(sk)
      secretKeyVec.push(sk)

      const pk = bls.publicKey()
      bls.getPublicKey(pk, sk)
      verVec.push(pk)
    }
    verificationVecs.push(verVec)

    // generate secert key shares for every one
    for (let q = 0; q < numOfPlayers; q++) {
      const sk = bls.secretKey()
      bls.secretKeyShare(sk, secretKeyVec, ids[q])
      secretKeyShares[q].push({
        sk: sk,
        id: i
      })
    }
  }

  for (let i = 0; i < numOfPlayers; i++) {
    const mySecretKeyShares = secretKeyShares[i]
    // verify the shares
    mySecretKeyShares.forEach(share => {
      const pk = bls.publicKey()
      const vvec = verificationVecs[share.id]
      bls.publicKeyShare(pk, vvec, ids[i])

      const pk2 = bls.publicKey()
      bls.getPublicKey(pk2, share.sk)

      console.log(bls.publicKeyIsEqual(pk, pk2))
    })

    const mySecretKey = mySecretKeyShares.pop().sk
    mySecretKeyShares.forEach(share => {
      bls.secretKeyAdd(mySecretKey, share.sk)
    })

    const pk = bls.publicKey()
    bls.getPublicKey(pk, mySecretKey)

    publicKeys.push({pk: pk, id: i})
  }

  // recover public key
  for (let i = 0; i < 3; i++) {
    const shareArray = shuffle(publicKeys).slice(0, threshold)
    const pks = shareArray.map(s => s.pk)
    const sids = shareArray.map(s => ids[s.id])
    const pk = bls.publicKey()

    bls.publicKeyRecover(pk, pks, sids)

    const publicKey = bls.publicKeySerialize(pk)
    console.log(Buffer.from(publicKey).toString('hex'))
  }
})
