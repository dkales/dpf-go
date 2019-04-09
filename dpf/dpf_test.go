package dpf

import (
	"testing"
)

func BenchmarkEvalFull(bench *testing.B) {
	logN := uint64(28)
	a,_ := Gen(0, logN)
	bench.ResetTimer()
	//fmt.Println("Ka: ", a)
	//fmt.Println("Kb: ", b)
	//for i:= uint64(0); i < (uint64(1) << logN); i++ {
	//	aa := dpf.Eval(a, i, logN)
	//	bb := dpf.Eval(b, i, logN)
	//	fmt.Println(i,"\t", aa,bb, aa^bb)
	//}
	for i := 0; i < bench.N; i++ {
		EvalFull(a, logN)
	}
}

func BenchmarkXor16(bench *testing.B) {
	a := new(block)
	b := new(block)
	c := new(block)
	for i := 0; i < bench.N; i++ {
		xor16(&c[0], &b[0], &a[0])
	}
}

func TestEval(test *testing.T) {
	logN := uint64(8)
	alpha := uint64(123)
	a,b := Gen(alpha, logN)
	for i:= uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval(a, i, logN)
		bb := Eval(b, i, logN)
		if (aa^bb == 1 && i != alpha) || (aa^bb == 0 && i == alpha) {
			test.Fail()
		}
	}
}

func TestEvalFull(test *testing.T) {
	logN := uint64(8)
	alpha := uint64(123)
	a,b := Gen(alpha, logN)
	aa := EvalFull(a, logN)
	bb := EvalFull(b, logN)
	for i:= uint64(0); i < (uint64(1) << logN); i++ {
		aaa := (aa[i/8] >> (i%8)) & 1
		bbb := (bb[i/8] >> (i%8)) & 1
		if (aaa^bbb == 1 && i != alpha) || (aaa^bbb == 0 && i == alpha) {
			test.Fail()
		}
	}
}
