import { describe, expect, test } from "bun:test";
import { MAX_DEPTH, parseJson } from "./json";

const nested = (levels: number, inner = "") => "[".repeat(levels) + inner + "]".repeat(levels);

describe("parseJson", () => {
  test("reads what JSON.parse reads, to 64 levels", () => {
    expect(MAX_DEPTH).toBe(64);
    expect(parseJson('{"a":[1,"x",null]}')).toEqual({ a: [1, "x", null] });
    expect(parseJson(nested(64))).toBeArray();
    expect(parseJson(nested(63, "1"))).toBeArray();
    const objects = '{"a":'.repeat(64) + "1" + "}".repeat(64);
    expect(parseJson(objects)).toBeObject();
  });

  test("refuses deeper nesting as a syntax error, before parsing", () => {
    for (const text of [nested(65), nested(64, "{}"), nested(30_000), `[${'{"a":'.repeat(64)}1${"}".repeat(64)}]`]) {
      expect(() => parseJson(text)).toThrow(SyntaxError);
    }
  });

  test("counts no bracket inside a string, escaped quotes included", () => {
    expect(parseJson(`["${"[{".repeat(100)}"]`)).toEqual(["[{".repeat(100)]);
    expect(parseJson(`["\\"${"[".repeat(100)}"]`)).toEqual([`"${"[".repeat(100)}`]);
    expect(parseJson(`["\\\\", ${nested(63)}]`)).toBeArray();
    expect(() => parseJson(`["\\\\", ${nested(64)}]`)).toThrow(SyntaxError);
  });

  test("still refuses what JSON.parse refuses", () => {
    for (const text of ["", "[", "{,}", "[1,]", "﻿{}", "'a'"]) expect(() => parseJson(text)).toThrow(SyntaxError);
  });
});
