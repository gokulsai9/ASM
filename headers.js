const fs = require("fs");

const headerData = JSON.parse(
  fs.readFileSync("./fingerprint_output.json", "utf8")
);

const securityHeaders = [
  {
    header: "Strict-Transport-Security",
    cwe: "CWE-523",
    cvssScore: 7.5,
  },
  {
    header: "X-Content-Type-Options",
    cwe: "CWE-16",
    cvssScore: 5.3,
  },
  {
    header: "X-Frame-Options",
    cwe: "CWE-1021",
    cvssScore: 6.5,
  },
  {
    header: "X-Xss-Protection",
    cwe: "CWE-79",
    cvssScore: 6.1,
  },
  {
    header: "Content-Security-Policy",
    cwe: "CWE-358",
    cvssScore: 8.3,
  },
];

const calculateRiskScore = (headersObject) => {
  let riskScore = 0;

  // Check for missing critical security headers and adjust risk score
  securityHeaders.forEach(({ header, cvssScore }) => {
    if (!headersObject.headers.hasOwnProperty(header)) {
      riskScore += cvssScore; // Add the CVSS score to the risk score if the header is missing
    }
  });

  // Check the status code
  const statusCode = headersObject.status_code;
  if (statusCode >= 500) {
    riskScore += 5; // High risk for server errors
  } else if (statusCode >= 400) {
    riskScore += 3; // Moderate risk for client errors
  }

  // Check if server information is exposed
  const serverInfo = headersObject.server || headersObject.headers["Server"];
  if (serverInfo && serverInfo !== "") {
    riskScore += 2; // Risk due to exposed server version
  }

  return riskScore;
};

const generateRiskReport = (headersData) => {
  const report = headersData.map((urlData) => {
    const riskScore = calculateRiskScore(urlData);
    return {
      url: urlData.url,
      riskScore: riskScore,
      status_code: urlData.status_code,
      server: urlData.server || urlData.headers["Server"] || "Not Exposed",
      missingHeaders: securityHeaders
        .filter(({ header }) => !urlData.headers.hasOwnProperty(header))
        .map(({ header, cwe, cvssScore }) => ({ header, cwe, cvssScore })),
    };
  });

  return report;
};

// Generate the risk report
const riskReport = generateRiskReport(headerData);

// Display or save the risk report
console.log(JSON.stringify(riskReport, null, 2));

// Save the report to a JSON file
fs.writeFileSync(
  "risk_report.json",
  JSON.stringify(riskReport, null, 2),
  "utf-8"
);

console.log("Risk report saved as 'risk_report.json'.");
