import { Base, greet } from "./base.ts";

function param(Base: unknown): void { new Base(); }
function local(): void { let Base: unknown; new Base(); }
function callShadow(greet: unknown): void { greet(); }
function throwShadow(Base: unknown): void { throw new Base(); }
function control(): void { new Base(); greet(); }
function outer(): void { let Base: unknown; class Local extends Base {} }
{ let Base: unknown; new Base(); }
const named = function Base(): void { new Base(); };
function nested(): void { { let Base: unknown; { let Base: unknown; new Base(); } } new Base(); }
function another(): void { new Base(); }
function abstractClassLocal(): void { abstract class greet {} greet(); }
function enumLocal(): void { enum greet { member } greet(); }
