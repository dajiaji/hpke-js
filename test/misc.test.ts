import { i2Osp, xor } from '../src/utils/misc';

describe('i2Osp', () => {

  describe('with valid params (5, 1)', () => {
    it('return correct result', () => {
      expect(i2Osp(5, 1)).toEqual(new Uint8Array([5]));
    });
  });

  describe('with valid params (5, 2)', () => {
    it('return correct result', () => {
      expect(i2Osp(5, 2)).toEqual(new Uint8Array([0, 5]));
    });
  });

  describe('with valid params (5, 3)', () => {
    it('return correct result', () => {
      expect(i2Osp(5, 3)).toEqual(new Uint8Array([0, 0, 5]));
    });
  });

  describe('with invalid n', () => {
    it('should throw Error', () => {
      expect(()=> i2Osp(256, 1)).toThrow('i2Osp: too large integer');
    });
  });

  describe('with invalid w (0)', () => {
    it('should throw Error', () => {
      expect(()=> i2Osp(255, 0)).toThrow('i2Osp: too small size');
    });
  });

  describe('with invalid w (negative value)', () => {
    it('should throw Error', () => {
      expect(()=> i2Osp(255, -1)).toThrow('i2Osp: too small size');
    });
  });
});

describe('xor', () => {

  describe('with valid params', () => {
    it('return correct result', () => {
      const a = new Uint8Array([0, 1, 1]);
      const b = new Uint8Array([1, 1, 0]);
      expect(xor(a, b)).toEqual(new Uint8Array([1, 0, 1]));
    });
  });

  describe('with different length inputs', () => {
    it('should throw Error', () => {
      const a = new Uint8Array([0, 1, 1]);
      const b = new Uint8Array([1, 1]);
      expect(()=> xor(a, b)).toThrow('xor: different length inputs');
    });
  });
});
