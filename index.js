module.exports = class Group {
  constuctor (bls, ids, id, threshold) {
    this.bls = bls
    this.ids = ids
    this.id = id
    this.threshold = threshold
  }

  setup () {
    const secretKeyVector = []
    const verificationVector = []
    const secretKeyShares = []

    for (let i = 0; i < this.threshold; i++) {
      const sk = this.bls.secretKey()
      this.bls.secretKeySetByCSPRNG(sk)
      secretKeyVector.push(sk)

      const pk = this.bls.publicKey()
      this.bls.getPublicKey(pk, sk)
      verificationVector.push(pk)
    }

    for (const id of this.ids) {
      const sk = this.bls.secretKey()
      this.bls.secretKeyShare(sk, secretKeyVector, id)
      secretKeyShares.push({
        sk: sk,
        toId: id
      })
    }

    return {
      secretKeyVector: secretKeyVector,
      verificationVector: verificationVector,
      secretKeyShares: secretKeyShares
    }
  }

  verifyShare (fromId, share, vvec) {
    const pk = this.bls.publicKey()
    this.bls.publicKeyShare(pk, vvec, this.id)

    const pk2 = this.bls.publicKey()
    this.bls.getPublicKey(pk2, share.sk)

    return this.bls.publicKeyIsEqual(pk, pk2)
  }

  recoverSecretKeyShare (secretKeyShares) {
    const skShare = secretKeyShares.pop()
    secretKeyShares.forEach(share => {
      this.bls.secretKeyAdd(skShare, share)
    })

    const pk = this.bls.publicKey()
    this.bls.getPublicKey(pk, skShare)

    return {
      secretKeyShare: skShare,
      publicKeyShare: pk
    }
  }

  recoverGroupPublicKey (publicKeyShares) {
    const pks = publicKeyShares.map(s => s.pk)
    const sids = publicKeyShares.map(s => s.id)
    const pk = this.bls.publicKey()

    this.bls.publicKeyRecover(pk, pks, sids)
    return pk
  }
}
