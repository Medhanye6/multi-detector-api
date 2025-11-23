// api/checkAccount.js (Node.js/Express-style handler)
import admin from 'firebase-admin';

// --- 1. Admin SDK Initialization ---
// IMPORTANT: This initialization block runs once on cold start.
// It relies on Vercel Environment Variables for credentials.

// Check if the Admin SDK is already initialized
if (!admin.apps.length) {
    try {
        // The service account JSON content is stored in a single Vercel ENV Variable 
        // named FIREBASE_SERVICE_ACCOUNT_JSON.
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);

        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            // Use your actual Firebase RTDB URL here
            databaseURL: process.env.FIREBASE_DATABASE_URL 
        });
    } catch (error) {
        console.error("Firebase Admin SDK Initialization Error:", error);
        // It's crucial to handle this error securely
    }
}

const db = admin.database();

export default async function handler(req, res) {
    // Only allow POST requests for this critical action
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { idToken, deviceData, action } = req.body;

    // --- 2. Security: Firebase ID Token Verification ---
    let userId;
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        userId = decodedToken.uid;
    } catch (error) {
        console.error("Token Verification Failed:", error.message);
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired ID Token' });
    }

    // --- 3. IP Address Retrieval ---
    // Vercel populates 'x-forwarded-for' with the client's IP
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0].trim() || 'unknown';
    
    // 4. Device Fingerprint Hash
    const deviceHash = deviceData ? JSON.stringify(deviceData).replace(/[\s\.]/g, '') : 'unknown';
    
    // --- 5. Log the Current Action (RTDB write) ---
    await db.ref(`user_logs/${userId}`).push({
        ip: ipAddress,
        deviceHash: deviceHash,
        timestamp: admin.database.ServerValue.TIMESTAMP,
        action: action || 'general_activity'
    });

    // --- 6. Multi-Detector Logic (RTDB lookup) ---

    // Look back at logs for the last 48 hours for a slightly wider net
    const fortyEightHoursAgo = Date.now() - (48 * 60 * 60 * 1000);

    const suspicionLevel = await checkSuspicion(userId, ipAddress, deviceHash, fortyEightHoursAgo);
    
    // --- 7. Enforcement & Response ---
    if (suspicionLevel.matchCount >= 3) {
        // High Suspicion: Block the action
        await db.ref(`admin_suspicion_queue/${userId}`).set({
             ip: ipAddress,
             ...suspicionLevel,
             reason: 'BLOCKED: Three or more matching accounts (IP or Device)',
             timestamp: admin.database.ServerValue.TIMESTAMP
        });
        return res.status(403).json({ 
            status: 'blocked', 
            message: 'High suspicion of multi-accounting. Action blocked.',
            suspicionLevel: suspicionLevel.matchCount
        });
    }

    return res.status(200).json({ 
        status: 'ok', 
        message: 'Action logged and checked.', 
        suspicionLevel: suspicionLevel.matchCount
    });
}

/**
 * Helper function to query the database for matching IPs and Devices.
 */
async function checkSuspicion(currentUserId, ipAddress, deviceHash, sinceTimestamp) {
    const suspiciousAccounts = new Set();

    // Check 1: Same IP Address
    const ipMatchesSnapshot = await db.ref('user_logs')
        .orderByChild('ip').equalTo(ipAddress)
        .once('value');

    ipMatchesSnapshot.forEach(userLogSnapshot => {
        const otherUserId = userLogSnapshot.key;
        if (otherUserId !== currentUserId) {
            userLogSnapshot.forEach(logEntrySnapshot => {
                const logEntry = logEntrySnapshot.val();
                if (logEntry.timestamp > sinceTimestamp) {
                    suspiciousAccounts.add(otherUserId);
                }
            });
        }
    });

    // Check 2: Same Device Hash
    const deviceMatchesSnapshot = await db.ref('user_logs')
        .orderByChild('deviceHash').equalTo(deviceHash)
        .once('value');
    
    deviceMatchesSnapshot.forEach(userLogSnapshot => {
        const otherUserId = userLogSnapshot.key;
        if (otherUserId !== currentUserId) {
             // Only add if not already flagged by IP for unique count
            suspiciousAccounts.add(otherUserId);
        }
    });

    return { 
        matchedUsers: Array.from(suspiciousAccounts),
        matchCount: suspiciousAccounts.size
    };
}