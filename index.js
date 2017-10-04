const bls = require('bls-lib')
const shuffle = require('array-shuffle')

bls.onModuleInit(() => {
  bls.init()
  const numOfPlayers = 5
  const threshold = 3

  const secretKeyShares = Array(numOfPlayers)
  const publicKeys = []
  const ids = []

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
    for (let i = 0; i < threshold; i++) {
      const sk = bls.secretKey()
      bls.secretKeySetByCSPRNG(sk)
      secretKeyVec.push(sk)
    }

    // generate secert key shares for every one
    for (let q = 0; q < numOfPlayers; q++) {
      const sk = bls.secretKey()
      bls.secretKeyShare(sk, secretKeyVec, ids[q])
      secretKeyShares[q].push(sk)
    }
  }

  for (let i = 0; i < numOfPlayers; i++) {
    const mySecretKey = secretKeyShares[i].pop()
    const mySecretKeyShares = secretKeyShares[i]
    mySecretKeyShares.forEach(sk => {
      bls.secretKeyAdd(mySecretKey, sk)
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
