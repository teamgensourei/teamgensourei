// テストスクリプト - ローカル開発用

const testConfig = {
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  testScratchUser: 'griffpatch', // 実在するScratchユーザー
  testEmail: 'test@example.com'
};

async function runTests() {
  console.log('🧪 Starting API tests...\n');

  // Test 1: Health Check
  console.log('Test 1: Health Check');
  try {
    const response = await fetch(`${testConfig.baseUrl}/health`);
    const data = await response.json();
    console.log('✅ Health check passed:', data);
  } catch (error) {
    console.log('❌ Health check failed:', error.message);
  }
  console.log('');

  // Test 2: Verify Scratch User
  console.log('Test 2: Verify Scratch User');
  try {
    const response = await fetch(`${testConfig.baseUrl}/api/verify-scratch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scratchUsername: testConfig.testScratchUser,
        email: testConfig.testEmail
      })
    });
    const data = await response.json();
    if (response.ok) {
      console.log('✅ Scratch verification passed:', data);
    } else {
      console.log('❌ Scratch verification failed:', data);
    }
  } catch (error) {
    console.log('❌ Scratch verification error:', error.message);
  }
  console.log('');

  // Test 3: Invalid Scratch User
  console.log('Test 3: Invalid Scratch User');
  try {
    const response = await fetch(`${testConfig.baseUrl}/api/verify-scratch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scratchUsername: 'thisshouldnotexist123456789',
        email: testConfig.testEmail
      })
    });
    const data = await response.json();
    if (!response.ok && data.error) {
      console.log('✅ Invalid user handling works:', data.error);
    } else {
      console.log('❌ Invalid user handling failed');
    }
  } catch (error) {
    console.log('❌ Invalid user test error:', error.message);
  }
  console.log('');

  console.log('🎉 Tests completed!\n');
  console.log('Next steps:');
  console.log('1. Create an account through the frontend');
  console.log('2. Test login functionality');
  console.log('3. Test authenticated endpoints');
}

// Run if called directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests, testConfig };
