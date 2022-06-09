// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.
/**
 * Package int provides helper functions for integerss.
 */
// Shim using 16-bit pieces.
function imulShim(a, b) {
    const ah = (a >>> 16) & 0xffff, al = a & 0xffff;
    const bh = (b >>> 16) & 0xffff, bl = b & 0xffff;
    return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
}
/** 32-bit integer multiplication.  */
// Use system Math.imul if available, otherwise use our shim.
export const mul = Math.imul ||
    imulShim;
/** 32-bit integer addition.  */
export function add(a, b) {
    return (a + b) | 0;
}
/**  32-bit integer subtraction.  */
export function sub(a, b) {
    return (a - b) | 0;
}
/** 32-bit integer left rotation */
export function rotl(x, n) {
    return x << n | x >>> (32 - n);
}
/** 32-bit integer left rotation */
export function rotr(x, n) {
    return x << (32 - n) | x >>> n;
}
function isIntegerShim(n) {
    return typeof n === "number" && isFinite(n) && Math.floor(n) === n;
}
/**
 * Returns true if the argument is an integer number.
 *
 * In ES2015, Number.isInteger.
 */
export const isInteger = Number.isInteger || isIntegerShim;
/**
 *  Math.pow(2, 53) - 1
 *
 *  In ES2015 Number.MAX_SAFE_INTEGER.
 */
export const MAX_SAFE_INTEGER = 9007199254740991;
/**
 * Returns true if the argument is a safe integer number
 * (-MIN_SAFE_INTEGER < number <= MAX_SAFE_INTEGER)
 *
 * In ES2015, Number.isSafeInteger.
 */
export const isSafeInteger = (n) => isInteger(n) && (n >= -MAX_SAFE_INTEGER && n <= MAX_SAFE_INTEGER);
