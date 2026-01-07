# Secret Management Guide for Key-Ching-Server

## Overview
You have two options for managing secrets in Google App Engine:

---

## ✅ Option 1: env.yaml File (Recommended for Quick Start)

### Setup:
1. **Create `env.yaml`** (already created) with your secrets
2. **Add to .gitignore** (already done)
3. **Deploy with both files**:
   ```bash
   gcloud app deploy app.yaml
   ```

### Pros:
- ✅ Simple and straightforward
- ✅ Works immediately
- ✅ No additional GCP setup needed

### Cons:
- ⚠️ Less secure - secrets are in plain text file
- ⚠️ Must keep env.yaml secure and never commit it
- ⚠️ Manual secret rotation

### How it works:
- `app.yaml` includes the `env.yaml` file
- All environment variables from both files are merged
- Your code accesses them via `process.env.VARIABLE_NAME`

---

## 🔐 Option 2: Google Secret Manager (Recommended for Production)

### Setup:
1. **Run the setup script**:
   ```bash
   chmod +x setup-secrets.sh
   ./setup-secrets.sh
   ```

2. **Modify your server.cjs** to load secrets:
   ```javascript
   // Add at the top of server.cjs
   const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
   
   async function accessSecretVersion(secretName) {
     const client = new SecretManagerServiceClient();
     const name = `projects/key-ching-server/secrets/${secretName}/versions/latest`;
     const [version] = await client.accessSecretVersion({ name });
     return version.payload.data.toString();
   }
   
   // Load secrets on startup
   async function loadSecrets() {
     if (process.env.NODE_ENV === 'production') {
       process.env.DB_PASSWORD = await accessSecretVersion('DB_PASSWORD');
       process.env.STRIPE_SECRET_KEY = await accessSecretVersion('STRIPE_SECRET_KEY');
       // ... load other secrets
     }
   }
   
   // Call before starting server
   loadSecrets().then(() => {
     server.listen(PORT, ...);
   });
   ```

3. **Install the package**:
   ```bash
   npm install @google-cloud/secret-manager
   ```

4. **Update app.yaml** to remove `includes: env.yaml`

### Pros:
- ✅ Highly secure - secrets encrypted at rest
- ✅ Centralized secret management
- ✅ Audit logs and access control
- ✅ Easy secret rotation
- ✅ No secrets in your codebase

### Cons:
- ⚠️ More complex setup
- ⚠️ Slight performance overhead (minimal)
- ⚠️ Additional GCP API costs (very small)

---

## 🚀 Current Deployment Commands

### Using env.yaml (Current Setup):
```bash
# Deploy to App Engine
gcloud app deploy

# The deployment will include both app.yaml and env.yaml
```

### Using GitHub Actions:
```bash
# Just push to main branch
git add .
git commit -m "Deploy to App Engine"
git push origin main

# GitHub Actions will handle deployment
# Make sure env.yaml is available in your workflow
```

---

## 🔒 Security Best Practices

### DO:
- ✅ Add `env.yaml` to `.gitignore` (done)
- ✅ Add `.env` to `.gitignore` (done)
- ✅ Use Secret Manager for production
- ✅ Rotate secrets regularly
- ✅ Use service account with minimal permissions

### DON'T:
- ❌ Commit `env.yaml` to git
- ❌ Commit `.env` to git
- ❌ Share secrets in chat/email
- ❌ Use production secrets in development

---

## 📝 Environment Variable Access in Code

Your code already uses:
```javascript
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'KeyChingDB',
  // ...
};
```

This works with both options automatically! ✅

---

## 🔄 For GitHub Actions Deployment

If using env.yaml with GitHub Actions, you need to add secrets to GitHub:

1. Go to your repo → Settings → Secrets and variables → Actions
2. Add each secret as a repository secret
3. Update `.github/workflows/deploy.yml` to create env.yaml during deployment:

```yaml
- name: Create env.yaml
  run: |
    cat > env.yaml << EOF
    env_variables:
      DB_PASSWORD: '${{ secrets.DB_PASSWORD }}'
      STRIPE_SECRET_KEY: '${{ secrets.STRIPE_SECRET_KEY }}'
      # ... other secrets
    EOF
```

---

## 📞 Need Help?

Check the secrets status:
```bash
# List all secrets in Secret Manager
gcloud secrets list --project=key-ching-server

# View secret metadata
gcloud secrets describe DB_PASSWORD --project=key-ching-server

# Test access
gcloud secrets versions access latest --secret="DB_PASSWORD" --project=key-ching-server
```
