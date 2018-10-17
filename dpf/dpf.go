package dpf

import (
	"crypto/rand"
	"sync"
)

type DPFkey []byte
type block [16]byte

var prfL *aesPrf
var prfR *aesPrf
var keyL = make([]uint32, 11*4)
var keyR = make([]uint32, 11*4)

var blockPool = sync.Pool{
	New : func() interface{} {
		return new(block)
	},
}

func init() {
	var prfkeyL = []byte{36,156,50,234,92,230,49,9,174,170,205,160,98,236,29,243}
	var prfkeyR = []byte{209, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}
	var errL, errR error
	prfL, errL = newCipher(prfkeyL)
	if errL != nil {
		panic("dpf: can't init AES")
	}
	prfR, errR = newCipher(prfkeyR)
	if errR != nil {
		panic("dpf: can't init AES")
	}
	expandKeyAsm(&prfkeyL[0], &keyL[0])
	expandKeyAsm(&prfkeyR[0], &keyR[0])
	//if cpu.X86.HasSSE2 == false || cpu.X86.HasAVX2 == false {
	//	panic("we need sse2 and avx")
	//}

}

func getT(in *byte) byte {
	return *in & 1
}

func clr(in *byte) {
	*in &= 0xFE
}

func convertBlock(in []byte) {
	//prfL.Encrypt(in, in)
	encryptAes128(&keyL[0], &in[0], &in[0])
}


func prg(seed, s0, s1 *byte) (byte, byte) {
	//prfL.Encrypt(s0, seed)
	encryptAes128(&keyL[0], s0, seed)
	t0 := getT(s0)
	clr(s0)
	//prfR.Encrypt(s1, seed)
	encryptAes128(&keyR[0], s0, seed)
	t1 := getT(s1)
	clr(s1)
	return t0, t1
}


func Gen(alpha uint64, logN uint64) (DPFkey, DPFkey) {
	if alpha >= (1<<logN) || logN > 63 {
		panic("dpf: invalid parameters")
	}
	var ka, kb DPFkey
	var CW []byte
	s0  := new(block)
	s1  := new(block)
	scw := new(block)
	rand.Read(s0[:])
	rand.Read(s1[:])

	t0 := getT(&s0[0])
	t1 := t0 ^ 1

	clr(&s0[0])
	clr(&s1[0])

	ka = append(ka, s0[:]...)
	ka = append(ka, t0)
	kb = append(kb, s1[:]...)
	kb = append(kb, t1)

	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}
	for i := uint64(0); i < stop; i++ {
		s0L := blockPool.Get().(*block)
		s0R := blockPool.Get().(*block)
		t0L, t0R := prg(&s0[0], &s0L[0], &s0R[0])
		s1L := blockPool.Get().(*block)
		s1R := blockPool.Get().(*block)
		t1L, t1R := prg(&s1[0], &s1L[0], &s1R[0])

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			//KEEP = R, LOSE = L
			xor16(&scw[0], &s0L[0], &s1L[0])
			tLCW := t0L ^ t1L
			tRCW := t0R ^ t1R ^ 1
			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			*s0 = *s0R
			if t0 != 0 {
				xor16(&s0[0], &s0[0], &scw[0])
			}
			*s1 = *s1R
			if t1 != 0 {
				xor16(&s1[0], &s1[0], &scw[0])
			}
			if t0 != 0 {
				t0 = t0R ^ tRCW
			} else {
				t0 = t0R
			}
			if t1 != 0 {
				t1 = t1R ^ tRCW
			} else {
				t1 = t1R
			}

		} else {
			//KEEP = L, LOSE = R
			xor16(&scw[0], &s0R[0], &s1R[0])
			tLCW := t0L ^ t1L ^ 1
			tRCW := t0R ^ t1R
			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			*s0 = *s0L
			if t0 != 0 {
				xor16(&s0[0], &s0[0], &scw[0])
			}
			*s1 = *s1L
			if t1 != 0 {
				xor16(&s1[0], &s1[0], &scw[0])
			}
			if t0 != 0 {
				t0 = t0L ^ tLCW
			} else {
				t0 = t0L
			}
			if t1 != 0 {
				t1 = t1L ^ tLCW
			} else {
				t1 = t1L
			}
		}
	}
	//convertBlock(s0[:])
	encryptAes128(&keyL[0], &s0[0], &s0[0])
	//convertBlock(s1[:])
	encryptAes128(&keyL[0], &s1[0], &s1[0])
	xor16(&scw[0], &s0[0], &s1[0])
	scw[(alpha&127)/8] ^= byte(1) << ((alpha&127)%8)
	CW = append(CW, scw[:]...)
	ka = append(ka, CW...)
	kb = append(kb, CW...)
	return ka, kb
}

func Eval(k DPFkey, x uint64, logN uint64) byte {
	s := new(block)
	sL := new(block)
	sR := new(block)
	copy(s[:], k[:16])
	t := k[16]

	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}

	for i := uint64(0); i < stop; i++ {
		tL, tR := prg(&s[0], &sL[0], &sR[0])
		if t != 0 {
			sCW := k[17 + i*18 : 17 + i*18 + 16]
			tLCW := k[17 + i*18 + 16]
			tRCW := k[17 + i*18 + 17]
			xor16(&sL[0], &sL[0], &sCW[0])
			xor16(&sR[0], &sR[0], &sCW[0])
			tL ^= tLCW
			tR ^= tRCW
		}
		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t = tR
		} else {
			*s = *sL
			t = tL
		}
	}
	//fmt.Println("Debug", s, t)
	//convertBlock(s[:])
	encryptAes128(&keyL[0], &s[0], &s[0])
	if t != 0 {
		xor16(&s[0], &s[0], &k[len(k)-16])
		return (s[(x&127)/8] >> ((x&127)%8)) & 1
	} else {
		return (s[(x&127)/8] >> ((x&127)%8)) & 1
	}
}

func evalFullRecursive(k DPFkey, s *block, t byte, lvl uint64, stop uint64, res []byte) []byte {
	if lvl == stop {
		encryptAes128(&keyL[0], &s[0], &s[0])
		if t != 0 {
			xor16(&s[0], &s[0], &k[len(k)-16])
			return append(res, s[:]...)
		} else {
			return append(res, s[:]...)
		}
	}
	sL := new(block) // blockPool.Get().(*block)
	sR := new(block) // blockPool.Get().(*block)
	tL, tR := prg(&s[0], &sL[0], &sR[0])
	if t != 0 {
		sCW := k[17 + lvl*18 : 17 + lvl*18 + 16]
		tLCW := k[17 + lvl*18 + 16]
		tRCW := k[17 + lvl*18 + 17]
		xor16(&sL[0], &sL[0], &sCW[0])
		xor16(&sR[0], &sR[0], &sCW[0])
		tL ^= tLCW
		tR ^= tRCW
	}
	res = evalFullRecursive(k, sL, tL, lvl+1, stop, res)
	res = evalFullRecursive(k, sR, tR, lvl+1, stop, res)
	//blockPool.Put(sL)
	//blockPool.Put(sR)
	return res
}

func EvalFull(key DPFkey, logN uint64) ([]byte) {
	s := new(block)
	copy(s[:], key[:16])
	t := key[16]
	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}
	return evalFullRecursive(key, s, t, 0, stop, make([]byte, 0, 1 << (logN -3)))
}