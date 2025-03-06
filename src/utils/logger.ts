import { LogLevel, LogMethod, SimpleLogger, SimpleLogOptions } from '@sphereon/ssi-types';

export class Logger extends SimpleLogger {
  static opts: SimpleLogOptions = {
    namespace       : 'bip340-2025-cryptosuite',
    eventName       : 'bip340-2025-cryptosuite',
    defaultLogLevel : LogLevel.INFO,
    methods         : [LogMethod.CONSOLE],
  };

  constructor(opts?: SimpleLogOptions) {
    super(opts ??= Logger.opts);
  }

  public static log(value: any, ...args: any[]) {
    this.log(value, ...args);
  }

  public static error(value: any, ...args: any[]) {
    this.error(value, ...args);
  }

  public static warn(value: any, ...args: any[]) {
    this.warn(value, ...args);
  }

  public static info(value: any, ...args: any[]) {
    this.info(value, ...args);
  }

  public static debug(value: any, ...args: any[]) {
    this.debug(value, ...args);
  }

  public static trace(value: any, ...args: any[]) {
    this.trace(value, ...args);
  }
}

const logger = (opts?: SimpleLogOptions) => new Logger(opts);

export { logger };