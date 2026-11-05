const acceptsType = t => t.split(";",1)[0].trim().toLowerCase()==="application/csp-report";

const inputs = {
    A: "application/csp-report",
    B: "application/csp-report; charset=UTF-8",
    C: "application/csp-report-fake",
    D: "text/plain",
    E: "Application/CSP-Report; charset=UTF-8",
    F: "application/csp-reporting",
    G: "application/csp-report+json"
};

for (const [name, value] of Object.entries(inputs)) {
    console.log(name,value, "->", acceptsType(value));
}

const check = (condition, message) => {if(!condition)throw new Error(message);};
check(acceptsType(inputs.A)===true, "A must be accepted");
check(acceptsType(inputs.B)===true, "B must be accepted");
check(acceptsType(inputs.C)===false, "C must be rejected");
check(acceptsType(inputs.D)===false, "D must be rejected");
check(acceptsType(inputs.E)===true, "E must be accepted");
check(acceptsType(inputs.F)===false, "F must be rejected");
check(acceptsType(inputs.G)===false, "G must be rejected");
console.log("PASS");

