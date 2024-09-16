const fs = require("fs");
const path = require("path");

async function ReadFile(filepath) {
  try {
    const inputFilePath = path.resolve(filepath, "ips.shodan");
    const outputFilePath = path.resolve(filepath, "output.json");

    if (!fs.existsSync(inputFilePath)) {
      throw new Error(`Input file not found: ${inputFilePath}`);
    }

    let inputData = fs.readFileSync(inputFilePath, {
      encoding: "utf8",
    });

    const jsonData = [];
    let currentDomain = "";
    let currentDetails = {};

    inputData.split("\n").forEach((line) => {
      if (line.trim() === "") return;

      const parts = line.trim().split(/\s+/);

      if (parts.length === 1) {
        if (currentDomain !== "") {
          jsonData.push({ domain: currentDomain, details: currentDetails });
          currentDetails = {};
        }
        currentDomain = parts[0];
      } else {
        const detailType = parts.shift();
        const value = parts.join(" ").replace(/^\w+\s+/, "");
        if (!currentDetails[detailType]) {
          currentDetails[detailType] = [];
        }
        currentDetails[detailType].push(value);
      }
    });

    if (currentDomain !== "") {
      jsonData.push({ domain: currentDomain, details: currentDetails });
    }

    fs.writeFileSync(outputFilePath, JSON.stringify(jsonData, null, 2));

    fs.unlinkSync(inputFilePath);

    console.log(`JSON data written to ${outputFilePath}`);
  } catch (error) {
    if (error.code === "ENOENT") {
      console.error("Error: The specified file does not exist.");
    } else {
      console.error("An error occurred:", error);
    }
  }
}

module.exports = ReadFile;
