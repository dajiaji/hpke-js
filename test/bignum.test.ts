import { Bignum } from '../src/utils/bignum';

describe('Bignum', () => {

  describe('set', () => {
    it('should throw error with different size of array', () => {
      const a = new Uint8Array([1, 0]);
      const b = new Uint8Array([1, 0, 0, 0]);
      const c = new Uint8Array([]);
      const d = new Uint8Array([1]);

      const num = new Bignum(3);

      // assert
      expect(() => { num.set(a); }).toThrow('Bignum.set: invalid argument');
      expect(() => { num.set(b); }).toThrow('Bignum.set: invalid argument');
      expect(() => { num.set(c); }).toThrow('Bignum.set: invalid argument');
      expect(() => { num.set(d); }).toThrow('Bignum.set: invalid argument');
    });
  });

  describe('lessThan', () => {
    it('should return proper result', () => {
      const a = new Uint8Array([1, 0, 0]);
      const b = new Uint8Array([1, 1, 0]);
      const c = new Uint8Array([0, 1, 0]);
      const d = new Uint8Array([1, 0, 0]);

      const num = new Bignum(3);
      num.set(a);

      // assert
      expect(num.lessThan(b)).toEqual(true);
      expect(num.lessThan(c)).toEqual(false);
      expect(num.lessThan(d)).toEqual(false);
    });
  });

  describe('lessThan', () => {
    it('should throw error with different size of array', () => {
      const a = new Uint8Array([1, 0]);
      const b = new Uint8Array([1, 0, 0, 0]);
      const c = new Uint8Array([]);
      const d = new Uint8Array([1]);

      const num = new Bignum(3);

      // assert
      expect(() => { num.lessThan(a); }).toThrow('Bignum.lessThan: invalid argument');
      expect(() => { num.lessThan(b); }).toThrow('Bignum.lessThan: invalid argument');
      expect(() => { num.lessThan(c); }).toThrow('Bignum.lessThan: invalid argument');
      expect(() => { num.lessThan(d); }).toThrow('Bignum.lessThan: invalid argument');
    });
  });

});
