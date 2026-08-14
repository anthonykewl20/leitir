import { Base, greet } from "./base.js";

function param(Base) { new Base(); }
function local() { let Base; new Base(); }
function callShadow(greet) { greet(); }
function throwShadow(Base) { throw new Base(); }
function control() { new Base(); greet(); }
function outer() { let Base; class Local extends Base {} }
{ let Base; new Base(); }
const named = function Base() { new Base(); };
function nested() { { let Base; { let Base; new Base(); } } new Base(); }
function another() { new Base(); }
function* generatorParameter(greet) { greet(); }
async function* asyncGeneratorParameter(greet) { greet(); }
