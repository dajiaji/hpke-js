import * as errors from '../src/errors';

describe('ValidationError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.ValidationError(undefined);

      // assert
      expect(err.name).toEqual('ValidationError');
      expect(err.message).toEqual('ValidationError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.ValidationError('failed');

      // assert
      expect(err.name).toEqual('ValidationError');
      expect(err.message).toEqual('ValidationError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.ValidationError(origin);

      // assert
      expect(err.name).toEqual('ValidationError');
      expect(err.message).toEqual('ValidationError: failed');
    });
  });
});

describe('DeserializeError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.DeserializeError(undefined);

      // assert
      expect(err.name).toEqual('DeserializeError');
      expect(err.message).toEqual('DeserializeError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.DeserializeError('failed');

      // assert
      expect(err.name).toEqual('DeserializeError');
      expect(err.message).toEqual('DeserializeError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.DeserializeError(origin);

      // assert
      expect(err.name).toEqual('DeserializeError');
      expect(err.message).toEqual('DeserializeError: failed');
    });
  });
});

describe('EncapError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.EncapError(undefined);

      // assert
      expect(err.name).toEqual('EncapError');
      expect(err.message).toEqual('EncapError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.EncapError('failed');

      // assert
      expect(err.name).toEqual('EncapError');
      expect(err.message).toEqual('EncapError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.EncapError(origin);

      // assert
      expect(err.name).toEqual('EncapError');
      expect(err.message).toEqual('EncapError: failed');
    });
  });
});

describe('DecapError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.DecapError(undefined);

      // assert
      expect(err.name).toEqual('DecapError');
      expect(err.message).toEqual('DecapError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.DecapError('failed');

      // assert
      expect(err.name).toEqual('DecapError');
      expect(err.message).toEqual('DecapError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.DecapError(origin);

      // assert
      expect(err.name).toEqual('DecapError');
      expect(err.message).toEqual('DecapError: failed');
    });
  });
});

describe('ExportError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.ExportError(undefined);

      // assert
      expect(err.name).toEqual('ExportError');
      expect(err.message).toEqual('ExportError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.ExportError('failed');

      // assert
      expect(err.name).toEqual('ExportError');
      expect(err.message).toEqual('ExportError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.ExportError(origin);

      // assert
      expect(err.name).toEqual('ExportError');
      expect(err.message).toEqual('ExportError: failed');
    });
  });
});

describe('SealError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.SealError(undefined);

      // assert
      expect(err.name).toEqual('SealError');
      expect(err.message).toEqual('SealError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.SealError('failed');

      // assert
      expect(err.name).toEqual('SealError');
      expect(err.message).toEqual('SealError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.SealError(origin);

      // assert
      expect(err.name).toEqual('SealError');
      expect(err.message).toEqual('SealError: failed');
    });
  });
});

describe('OpenError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.OpenError(undefined);

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.OpenError('failed');

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.OpenError(origin);

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError: failed');
    });
  });
});

describe('MessageLimitReachedError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.MessageLimitReachedError(undefined);

      // assert
      expect(err.name).toEqual('MessageLimitReachedError');
      expect(err.message).toEqual('MessageLimitReachedError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.MessageLimitReachedError('failed');

      // assert
      expect(err.name).toEqual('MessageLimitReachedError');
      expect(err.message).toEqual('MessageLimitReachedError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.OpenError(origin);

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError: failed');
    });
  });
});

describe('DeriveKeyPairError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.DeriveKeyPairError(undefined);

      // assert
      expect(err.name).toEqual('DeriveKeyPairError');
      expect(err.message).toEqual('DeriveKeyPairError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.DeriveKeyPairError('failed');

      // assert
      expect(err.name).toEqual('DeriveKeyPairError');
      expect(err.message).toEqual('DeriveKeyPairError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.OpenError(origin);

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError: failed');
    });
  });
});

describe('NotSupportedError', () => {

  describe('constructor with neigher string or Error', () => {
    it('should have valid name and message', () => {
      const err = new errors.NotSupportedError(undefined);

      // assert
      expect(err.name).toEqual('NotSupportedError');
      expect(err.message).toEqual('NotSupportedError');
    });
  });

  describe('constructor with string', () => {
    it('should have valid name and message', () => {
      const err = new errors.NotSupportedError('failed');

      // assert
      expect(err.name).toEqual('NotSupportedError');
      expect(err.message).toEqual('NotSupportedError: failed');
    });
  });

  describe('constructor with another Error', () => {
    it('should have valid name and message', () => {
      const origin = new Error('failed');
      const err = new errors.OpenError(origin);

      // assert
      expect(err.name).toEqual('OpenError');
      expect(err.message).toEqual('OpenError: failed');
    });
  });
});
