const child_process = require("child_process");
const ReadFile = require("./middleware/app");
const fs = require("fs");
const path = require("path");
const domain = process.argv[2];

const SubsPATH = "/workspaces/ASM/subscripts/";

const subsFunction = async () => {
    try {
        const execSync = child_process.execSync;
        execSync(`${SubsPATH}subs.sh ${domain} active`);
        await subsreadFile(`${SubsPATH}files/final.txt`);
    } catch (error) {
        console.log("Error in subsFunction:", error.message);
    }
};

async function Return_IPS() {
    try {
        const allIPs = [];
        let jsonData = fs.readFileSync(`${SubsPATH}output.json`, {
            encoding: "utf-8",
        });
        jsonData = JSON.parse(jsonData);
        jsonData.forEach((domainData) => {
            const details = domainData.details;
            Object.values(details).forEach((ipList) => {
                allIPs.push(...ipList.filter((item) => /^[0-9.]+$/.test(item)));
            });
        });
        const uniqueIPs = [...new Set(allIPs)];
        return uniqueIPs;
    } catch (error) {
        console.log("Error in Return_IPS:", error.message);
    }
}



const subsreadFile = async (filePath) => {
    try {
        fs.readFile(filePath, "utf8", (err, data) => {
            if (err) throw err;
            console.log(data);
        });
    } catch (error) {
        console.log("Error in subsreadFile:", error.message);
    }
};

async function ReadCurrentIPS() {
    try {
        const ips = fs.readFileSync(`${SubsPATH}/ips`, { encoding: "utf-8" }).split("\n");
        const allips = await Return_IPS();
        const combineIPS = new Set([...ips, ...allips]);
        const uniqueIPS = [...combineIPS];
        return uniqueIPS;
    } catch (error) {
        console.log("Error in ReadCurrentIPS:", error.message);
    }
}

const ipsFunction = async () => {
    try {
        const execSync = child_process.execSync;

        // Assuming SubsPATH, domain, and ReadFile functions are defined elsewhere
        execSync(`${SubsPATH}IPS.sh ${SubsPATH}ips ${SubsPATH}/files/final.txt ${domain}`);

        await ReadFile(SubsPATH);

        const setofips = await ReadCurrentIPS();
        console.log(setofips)
        
        // Filter out empty strings from the set of IPs
        const filteredIPs = setofips.filter(ip => ip.trim() !== '');

        // Write filtered IPs to the final.txt file
        fs.writeFileSync(`${SubsPATH}/files/ips.txt`, filteredIPs.join('\n'), 'utf-8');

        console.log("IPs have been successfully written to the file.");
    } catch (error) {
        console.log("Error in ipsFunction:", error.message);
    }
};

async function SSLScript() {
    try {
        await child_process.execSync(`${SubsPATH}ssl.sh`, { stdio: "ignore" });
        await SSLreadFile();
    } catch (error) {
        console.log("Error in SSLScript:", error.message);
    }
}

async function SSLreadFile() {
    const filePath = `${SubsPATH}files/ssl.json`;
    try {
        const data = await fs.readFileSync(filePath, { encoding: "utf-8" });
        const filteredData = JSON.parse(data).filter(
            (item) =>
                item.id !== "service" &&
                item.id !== "engine_problem" &&
                item.id !== "scanProblem" &&
                item.finding.includes("VULNERABLE")
        );
        console.log(filteredData);
    } catch (error) {
        console.error(`Error reading file ${filePath}:`, error.message);
    } finally {
        try {
            fs.unlinkSync(filePath);
        } catch (error) {
            console.error(`Error deleting file ${filePath}:`, error.message);
        }
    }
}


async function ReconRunner() {
  try {
      // Execute the recon.sh script
      const pre_script = `${SubsPATH}recon.sh ${SubsPATH}files/final.txt`;
      console.log(`Executing script: ${pre_script}`);
      
      // Await the completion of the execSync call
      await child_process.execSync(pre_script, { stdio: 'inherit' });
      console.log("Script execution completed.");

      // Path to the output file
      const outputFilePath = path.resolve(SubsPATH, "files/recon.json");

      // Check if the output file exists
      if (fs.existsSync(outputFilePath)) {
          const readFile = fs.readFileSync(outputFilePath, { encoding: "utf8" }).split(/\n/);

          // Process each line in the output file
          readFile.forEach((line) => {
              try {
                  if (line.trim() !== "") {
                      const afparse = JSON.parse(line);
                      console.log(afparse);
                  }
              } catch (parseError) {
                  console.error("Error parsing JSON:", parseError);
              }
          });
      } else {
          console.log("output.json does not exist");
      }
  } catch (error) {
      console.error("Error in ReconRunner:", error.message);
  }
}

async function HeadersRunner() {

    const pre_script = `${SubsPATH}appcleapup.sh ${SubsPATH}files/final.txt`;
    console.log(`Executing script: ${pre_script}`);
    
    // Await the completion of the execSync call
    await child_process.execSync(pre_script, { stdio: 'ignore' });
    console.log("Script execution completed.");

    // Path to the output file
    const outputFilePath = path.resolve(SubsPATH, "fingerprint_output.json");
    if (fs.existsSync(outputFilePath)) {
        try {
            const readFile = fs.readFileSync(outputFilePath, { encoding: "utf8" });
            const afparse = JSON.parse(readFile);
            console.log(afparse);
            fs.unlinkSync(outputFilePath);
            console.log("output.json is removed");
        } catch (error) {
            console.error("Error in HeadersRunner:", error.message);
        }
    } else {
        console.log("output.json does not exist");
    }
}

const FScriptRunner = async() =>{
        const pre_script = `python3 ${SubsPATH}fierce/fierce.py --domain ${domain} --subdomain-file ${SubsPATH}fierce/lists/default.txt --wide --traverse 10 --output ${SubsPATH}foutput.json`
        console.log(pre_script)
        let command = child_process.execSync(pre_script);
       let content = await FRead();
       console.log(content)
}

async function filterSubdomains() {
    try {
        const finalFilePath = `${SubsPATH}files/final.txt`;
        const defaultFilePath = `${SubsPATH}fierce/lists/default.txt`;

        // Read subdomains from final.txt
        const finalData = fs.readFileSync(finalFilePath, "utf8");
        const subdomains = finalData.split("\n").filter(line => line.trim() !== "");

        // Read existing subdomains from default.txt
        let existingData = [];
        if (fs.existsSync(defaultFilePath)) {
            const existingFileData = fs.readFileSync(defaultFilePath, "utf8");
            existingData = existingFileData.split("\n").filter(line => line.trim() !== "");
        }

        const mainDomainParts = domain.split(".");
        const filteredSubdomains = subdomains.map(subdomain => {
            const parts = subdomain.split(".");
            if (parts.length > mainDomainParts.length) {
                const firstParts = parts.slice(0, -2); // Exclude the last two parts
                switch (firstParts.length) {
                    default:
                        return firstParts.join("."); // Return the first parts
                }
            }
            return null;
        }).filter(part => part !== null);

        // Combine new and existing subdomains and remove duplicates
        const uniqueSubdomains = [...new Set([...existingData, ...filteredSubdomains])];

        // Write the unique subdomains back to default.txt
        fs.writeFileSync(defaultFilePath, uniqueSubdomains.join("\n") + "\n");

        return uniqueSubdomains;
    } catch (error) {
        console.error("Error reading or processing files:", error.message);
        return [];
    }
}


const FRead = async () =>{
    let data = fs.readFileSync(`${SubsPATH}foutput.json`, { encoding: "utf-8" });
    data = JSON.parse(data)
    return data
}

const SSLRunner  = async () =>{
    let runner_script = `${SubsPATH}SSLChecker/ssl ${SubsPATH}files/ips.txt ${SubsPATH}SSLChecker/ca.crt`

    console.log(runner_script)
    let command = child_process.execSync(runner_script);
    await readSSLChecker()
}

const readSSLChecker = async() =>{
    let data = fs.readFileSync(`/workspaces/ASM/output.json`, { encoding: "utf-8" });
    data = JSON.parse(data)
    console.log(data)
}

const main = async () => {
    try {
        await subsFunction();
        await ipsFunction();
        await SSLScript();
        await ReconRunner();
        await HeadersRunner();
        await filterSubdomains();
        await FScriptRunner();
        await SSLRunner()
        
    } catch (error) {
        console.error("Error in main function:", error);
    }
};

main()
