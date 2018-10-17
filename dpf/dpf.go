package dpf

import (
	"crypto/rand"
)

type DPFkey []byte
var prfL *aesPrf
var prfR *aesPrf

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
	//if cpu.X86.HasSSE2 == false || cpu.X86.HasAVX2 == false {
	//	panic("we need sse2 and avx")
	//}

}

func getT(in []byte) byte {
	return in[0] & 1
}

func clr(in []byte) {
	in[0] &= 0xFE
}

func convertBlock(in []byte) {
	prfL.Encrypt(in, in)
}


func prg(seed []byte) ([]byte, byte, []byte, byte) {
	var s0 = make([]byte, 16)
	var s1 = make([]byte, 16)
	prfL.Encrypt(s0, seed)
	t0 := getT(s0)
	clr(s0)
	prfR.Encrypt(s1, seed)
	t1 := getT(s1)
	clr(s1)
	return s0, t0, s1, t1
}


func Gen(alpha uint64, logN uint64) (DPFkey, DPFkey) {
	if alpha >= (1<<logN) || logN > 63 {
		panic("dpf: invalid parameters")
	}
	var ka, kb DPFkey
	var CW []byte
	s0 := make([]byte, 16)
	s1 := make([]byte, 16)
	scw := make([]byte, 16)
	rand.Read(s0)
	rand.Read(s1)

	t0 := getT(s0)
	t1 := t0 ^ 1

	clr(s0)
	clr(s1)

	ka = append(ka, s0...)
	ka = append(ka, t0)
	kb = append(kb, s1...)
	kb = append(kb, t1)

	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}
	for i := uint64(0); i < stop; i++ {
		s0L, t0L, s0R, t0R := prg(s0)
		s1L, t1L, s1R, t1R := prg(s1)

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			//KEEP = R, LOSE = L
			xorWords(scw, s0L, s1L)
			tLCW := t0L ^ t1L
			tRCW := t0R ^ t1R ^ 1
			CW = append(CW, scw...)
			CW = append(CW, tLCW, tRCW)
			s0 = s0R
			if t0 != 0 {
				xorWords(s0, s0, scw)
			}
			s1 = s1R
			if t1 != 0 {
				xorWords(s1, s1, scw)
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
			xorWords(scw, s0R, s1R)
			tLCW := t0L ^ t1L ^ 1
			tRCW := t0R ^ t1R
			CW = append(CW, scw...)
			CW = append(CW, tLCW, tRCW)
			s0 = s0L
			if t0 != 0 {
				xorWords(s0, s0, scw)
			}
			s1 = s1L
			if t1 != 0 {
				xorWords(s1, s1, scw)
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
	convertBlock(s0)
	convertBlock(s1)
	xorWords(scw, s0, s1)
	scw[(alpha&127)/8] ^= byte(1) << ((alpha&127)%8)
	CW = append(CW, scw...)
	ka = append(ka, CW...)
	kb = append(kb, CW...)
	return ka, kb
}

func Eval(k DPFkey, x uint64, logN uint64) byte {
	s := make([]byte, 16)
	copy(s, k[:16])
	t := k[16]

	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}

	for i := uint64(0); i < stop; i++ {
		sL, tL, sR, tR := prg(s)
		if t != 0 {
			sCW := k[17 + i*18 : 17 + i*18 + 16]
			tLCW := k[17 + i*18 + 16]
			tRCW := k[17 + i*18 + 17]
			xorWords(sL, sL, sCW)
			xorWords(sR, sR, sCW)
			tL ^= tLCW
			tR ^= tRCW
		}
		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			s = sR
			t = tR
		} else {
			s = sL
			t = tL
		}
	}
	//fmt.Println("Debug", s, t)
	if t != 0 {
		convertBlock(s)
		xorWords(s, s, k[len(k)-16:])
		return (s[(x&127)/8] >> ((x&127)%8)) & 1
	} else {
		convertBlock(s)
		return (s[(x&127)/8] >> ((x&127)%8)) & 1
	}
}

func evalFullRecursive(k DPFkey, s []byte, t byte, lvl uint64, stop uint64, res []byte) []byte {
	if lvl == stop {
		ss := append([]byte(nil), s...)
		if t != 0 {
			convertBlock(ss)
			xorWords(ss, ss, k[len(k)-16:])
			return append(res, ss...)
		} else {
			convertBlock(ss)
			return append(res, ss...)
		}
	}
	sL, tL, sR, tR := prg(s)
	if t != 0 {
		sCW := k[17 + lvl*18 : 17 + lvl*18 + 16]
		tLCW := k[17 + lvl*18 + 16]
		tRCW := k[17 + lvl*18 + 17]
		xorWords(sL, sL, sCW)
		xorWords(sR, sR, sCW)
		tL ^= tLCW
		tR ^= tRCW
	}
	res = evalFullRecursive(k, sL, tL, lvl+1, stop, res)
	res = evalFullRecursive(k, sR, tR, lvl+1, stop, res)
	return res
}

func EvalFull(key DPFkey, logN uint64) ([]byte) {
	s := make([]byte, 16)
	copy(s, key[:16])
	t := key[16]
	stop := uint64(0)
	if logN >= 7 {
		stop = logN - 7
	}
	return evalFullRecursive(key, s, t, 0, stop, []byte(nil))
}