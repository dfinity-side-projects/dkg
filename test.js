const bls = require('bls-lib')
const shuffle = require('array-shuffle')
const dkg = require('./')

bls.onModuleInit(() => {
  bls.init()
  const threshold = 3

  const players = []
  const ids = [0, 1, 2, 3, 4].map(i => Buffer.from([i]))

  // set up master key share
  for (let i = 0; i < ids.length; i++) {
    const player = dkg.setup(bls, ids, threshold)
    player.id = i
    player.recievedShares = []
    players.push(player)
  }

  // all the plays public post their verification vectors
  const verificationVecs = players.map(player => player.verificationVector)

  // ever player sends there shares to all the players
  players.forEach(player => {
    player.secretKeyShares.forEach(skShare => {
      const to = skShare.to[0]
      skShare.from = player.id
      players[to].recievedShares.push(skShare)
    })
  })

  // verify the shares
  players.forEach(player => {
    player.recievedShares.forEach(rShare => {
      const fromId = rShare.from
      const vvec = verificationVecs[fromId]
      const valid = dkg.verifyShare(bls, ids[player.id], rShare.secretKey, vvec)
      console.log(valid)
    })
  })

  // recover the share for the group
  players.forEach(player => {
    player.share = dkg.keyShareRecover(bls, player.recievedShares)
  })

  // recover public key
  for (let i = 0; i < 6; i++) {
    const splayers = shuffle(players.slice(0))
    const shares = splayers.map(player => {
      return {
        publicKey: player.share.publicKey,
        id: ids[player.id]
      }
    })

    const pk = dkg.publicKeyRecover(bls, shares, threshold)
    const publicKey = bls.publicKeySerialize(pk)
    console.log(Buffer.from(publicKey).toString('hex'))
  }
})
