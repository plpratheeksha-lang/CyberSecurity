// ==========================================
// CYBERSHIELD RISK ANALYSIS ENGINE
// ==========================================

// Warning indicators and their scores

const phishingPatterns = [
    { words: ["verify", "verification"], score: 10, reason: "Verification request" },
    { words: ["otp", "one time password"], score: 20, reason: "OTP request" },
    { words: ["password", "login", "username"], score: 20, reason: "Credential-related request" },
    { words: ["account blocked", "account suspended", "account will be blocked"], score: 15, reason: "Account threat" },
    { words: ["click here", "click the link"], score: 10, reason: "Urgent link instruction" },
    { words: ["urgent", "immediately", "act now"], score: 10, reason: "Urgent language" }
];

const arrestPatterns = [
    { words: ["digital arrest"], score: 25, reason: "Digital-arrest wording" },
    { words: ["arrest", "arrested"], score: 25, reason: "Arrest threat" },
    { words: ["police", "cbi", "cyber crime"], score: 15, reason: "Authority-related wording" },
    { words: ["court", "warrant", "legal case"], score: 15, reason: "Legal threat" },
    { words: ["money laundering"], score: 15, reason: "Financial-crime accusation" },
    { words: ["investigation"], score: 10, reason: "Investigation-related wording" }
];

const financialPatterns = [
    { words: ["pay", "payment", "transfer money"], score: 20, reason: "Payment request" },
    { words: ["upi", "bank account", "account number"], score: 15, reason: "Financial information request" },
    { words: ["refund", "prize", "reward", "winner"], score: 10, reason: "Financial/reward claim" }
];


// ==========================================
// ANALYZE INPUT
// ==========================================

function analyzeInput() {

    const inputElement = document.getElementById("userInput");

    if (!inputElement) {
        return;
    }

    const input = inputElement.value.trim().toLowerCase();

    if (input === "") {
        alert("Please enter a message or URL first.");
        return;
    }

    let score = 0;

    let indicators = [];

    let breakdown = [];

    let phishingFound = false;
    let arrestFound = false;
    let financialFound = false;


    // ------------------------------------------
    // Check phishing patterns
    // ------------------------------------------

    phishingPatterns.forEach(pattern => {

        if (containsAny(input, pattern.words)) {

            score += pattern.score;

            indicators.push(pattern.reason);

            breakdown.push({
                reason: pattern.reason,
                score: pattern.score
            });

            phishingFound = true;
        }

    });


    // ------------------------------------------
    // Check digital arrest patterns
    // ------------------------------------------

    arrestPatterns.forEach(pattern => {

        if (containsAny(input, pattern.words)) {

            score += pattern.score;

            indicators.push(pattern.reason);

            breakdown.push({
                reason: pattern.reason,
                score: pattern.score
            });

            arrestFound = true;
        }

    });


    // ------------------------------------------
    // Check financial patterns
    // ------------------------------------------

    financialPatterns.forEach(pattern => {

        if (containsAny(input, pattern.words)) {

            score += pattern.score;

            indicators.push(pattern.reason);

            breakdown.push({
                reason: pattern.reason,
                score: pattern.score
            });

            financialFound = true;
        }

    });


    // ------------------------------------------
    // URL analysis
    // ------------------------------------------

    const urlResult = analyzeURL(input);

    if (urlResult.detected) {

        score += urlResult.score;

        indicators.push(urlResult.reason);

        breakdown.push({
            reason: urlResult.reason,
            score: urlResult.score
        });
    }


    // ------------------------------------------
    // Prevent score above 100
    // ------------------------------------------

    score = Math.min(score, 100);


    // ------------------------------------------
    // Determine risk level
    // ------------------------------------------

    let riskLevel;

    if (score >= 61) {

        riskLevel = "HIGH RISK";

    } else if (score >= 31) {

        riskLevel = "MEDIUM RISK";

    } else {

        riskLevel = "LOW RISK";
    }


    // ------------------------------------------
    // Determine threat category
    // ------------------------------------------

    let category = "General / No Strong Threat Pattern";

    if (arrestFound) {

        category = "Possible Digital-Arrest Scam";

    } else if (phishingFound) {

        category = "Possible Phishing";

    } else if (financialFound) {

        category = "Possible Financial Scam";

    } else if (urlResult.detected) {

        category = "Suspicious URL Pattern";
    }


    // ------------------------------------------
    // Safety recommendation
    // ------------------------------------------

    let recommendation;

    if (score >= 61) {

        recommendation =
            "Do not click suspicious links or share OTPs, passwords, " +
            "bank details or other sensitive information. Verify the " +
            "request using an official channel.";

    } else if (score >= 31) {

        recommendation =
            "Be cautious. Check the sender, verify the request " +
            "independently and avoid sharing sensitive information.";

    } else {

        recommendation =
            "No strong predefined warning pattern was detected. " +
            "Still verify unexpected messages before taking action.";
    }


    // ------------------------------------------
    // Display result
    // ------------------------------------------

    displayResult(
        score,
        riskLevel,
        category,
        indicators,
        breakdown,
        recommendation
    );
}


// ==========================================
// CHECK WHETHER ANY KEYWORD EXISTS
// ==========================================

function containsAny(text, words) {

    return words.some(word => text.includes(word));
}


// ==========================================
// URL ANALYSIS
// ==========================================

function analyzeURL(input) {

    const urlPattern = /(https?:\/\/[^\s]+)/i;

    const match = input.match(urlPattern);

    if (!match) {

        return {
            detected: false,
            score: 0,
            reason: ""
        };
    }

    const url = match[0];

    let score = 0;

    let reasons = [];


    // HTTP instead of HTTPS

    if (url.startsWith("http://")) {

        score += 10;

        reasons.push("HTTP URL detected");
    }


    // Very long URL

    if (url.length > 100) {

        score += 10;

        reasons.push("Unusually long URL");
    }


    // IP address instead of domain name

    const ipPattern =
        /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i;

    if (ipPattern.test(url)) {

        score += 20;

        reasons.push("IP-address URL detected");
    }


    // Suspicious words in URL

    const suspiciousURLWords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "free",
        "claim",
        "bonus"
    ];

    if (containsAny(url.toLowerCase(), suspiciousURLWords)) {

        score += 10;

        reasons.push("Sensitive or suspicious URL wording");
    }


    if (score === 0) {

        return {
            detected: false,
            score: 0,
            reason: ""
        };
    }


    return {
        detected: true,
        score: score,
        reason: reasons.join(", ")
    };
}


// ==========================================
// DISPLAY RESULT
// ==========================================

function displayResult(
    score,
    riskLevel,
    category,
    indicators,
    breakdown,
    recommendation
) {

    const resultSection =
        document.getElementById("resultSection");

    const riskScore =
        document.getElementById("riskScore");

    const riskLevelElement =
        document.getElementById("riskLevel");

    const categoryElement =
        document.getElementById("threatCategory");

    const indicatorList =
        document.getElementById("indicatorList");

    const breakdownElement =
        document.getElementById("breakdown");

    const recommendationElement =
        document.getElementById("recommendation");


    // Score

    riskScore.textContent = score;


    // Risk level

    riskLevelElement.textContent = riskLevel;


    // Category

    categoryElement.textContent = category;


    // Indicators

    indicatorList.innerHTML = "";


    if (indicators.length === 0) {

        const li = document.createElement("li");

        li.textContent =
            "No strong predefined warning indicator detected.";

        indicatorList.appendChild(li);

    } else {

        indicators.forEach(indicator => {

            const li = document.createElement("li");

            li.textContent = "✓ " + indicator;

            indicatorList.appendChild(li);
        });
    }


    // Breakdown

    if (breakdown.length === 0) {

        breakdownElement.innerHTML =
            "<p>No risk points added.</p>";

    } else {

        breakdownElement.innerHTML = "";

        breakdown.forEach(item => {

            const row = document.createElement("div");

            row.className = "breakdown-row";

            row.innerHTML = `
                <span>${item.reason}</span>
                <strong>+${item.score}</strong>
            `;

            breakdownElement.appendChild(row);
        });
    }


    // Recommendation

    recommendationElement.textContent =
        recommendation;


    // Show results

    resultSection.style.display = "block";


    // Scroll to result

    resultSection.scrollIntoView({
        behavior: "smooth"
    });
}


// ==========================================
// LOAD EXAMPLE MESSAGES
// ==========================================

function loadExample(type) {

    const input =
        document.getElementById("userInput");


    if (type === "phishing") {

        input.value =
            "URGENT! Your bank account will be blocked. " +
            "Verify your OTP immediately by clicking this link: " +
            "http://example-login.com";
    }


    else if (type === "arrest") {

        input.value =
            "We are from Cyber Crime Police. " +
            "You are involved in a money laundering case. " +
            "You are under digital arrest. " +
            "Transfer money immediately.";
    }


    else if (type === "normal") {

        input.value =
            "Your college timetable for Monday has been updated. " +
            "Please check the official college notice board.";
    }
}


// ==========================================
// CLEAR ANALYZER
// ==========================================

function clearAnalyzer() {

    const input =
        document.getElementById("userInput");

    input.value = "";

    document.getElementById("riskScore").textContent = "0";

    document.getElementById("riskLevel").textContent = "—";

    document.getElementById("threatCategory").textContent = "—";

    document.getElementById("indicatorList").innerHTML =
        "<li>No analysis yet.</li>";

    document.getElementById("breakdown").innerHTML =
        "No analysis yet.";

    document.getElementById("recommendation").textContent =
        "Enter suspicious content and click Analyze Risk.";
}