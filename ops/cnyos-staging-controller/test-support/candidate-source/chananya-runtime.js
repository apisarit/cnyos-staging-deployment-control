(() => {
  'use strict';
  if (window.ChananyaRuntime) return;

  let db = null;
  const deploymentConfig = () => window.CLINICAL_OS_CONFIG || {};
  const cfg = () => {
    const deployment = deploymentConfig();
    const database = deployment.database || {};
    const legacy = window.CHANANYA_AUTH || {};
    return {
      url: database.url || legacy.url || legacy.supabaseUrl,
      publishableKey: database.publishableKey || legacy.publishableKey || legacy.anonKey
    };
  };

  function getDb() {
    if (db) return db;
    if (deploymentConfig().safety?.previewLocked === true) {
      throw new Error('Deploy Preview database access is locked; use the read-only UI review');
    }
    if (!window.supabase) throw new Error('Supabase client library is not loaded');
    const c = cfg();
    const url = c.url || c.supabaseUrl;
    const key = c.publishableKey;
    if (!url || !key) throw new Error('Clinical OS database configuration is missing');
    db = window.supabase.createClient(url, key, {
      auth: { flowType: 'pkce', persistSession: true, autoRefreshToken: true }
    });
    return db;
  }

  const normalizeRole = value => String(value || '').trim().toLowerCase();

  function rolesOf(profile) {
    const membershipRole = normalizeRole(profile?.clinic_role || profile?.role) || 'viewer';
    const operationalRole = membershipRole === 'owner' ? 'admin' : membershipRole;
    const systemRole = normalizeRole(profile?.system_role) || 'staff';
    const effectiveRole = systemRole === 'super_admin'
      ? 'super_admin'
      : systemRole === 'admin' || operationalRole === 'admin'
        ? 'admin'
        : operationalRole;

    // One account has one active department. System admin is governance-only;
    // it never inherits the underlying clinical/pharmacy/production role.
    // Only super_admin receives the cross-workspace override.
    const grantedRoles = Object.freeze([effectiveRole]);
    return Object.freeze({
      clinicId: profile?.clinic_id || null,
      clinicRole: membershipRole,
      operationalRole,
      systemRole,
      effectiveRole,
      accessContextReady: profile?.access_context_ready === true,
      grantedRoles
    });
  }

  function roleOf(profile) {
    return rolesOf(profile).effectiveRole;
  }

  const permissions = Object.freeze({
    operations_view: ['super_admin','admin','practitioner','doctor','reception','pharmacy','production','inventory','quality','billing','viewer'],
    knowledge_read: ['super_admin','practitioner','doctor','pharmacy','production','inventory'],
    luopan_read: ['super_admin','admin','practitioner','doctor','reception','pharmacy','production','inventory','quality','billing','viewer'],
    clinical_read: ['super_admin','practitioner','doctor'],
    clinical_write: ['super_admin','practitioner','doctor'],
    patient_registry: ['super_admin','practitioner','doctor','reception'],
    patient_checkin: ['super_admin','practitioner','doctor','reception'],
    patient_identity_link: ['super_admin','practitioner','doctor','reception'],
    appointments_operate: ['super_admin','reception'],
    appointments_view: ['super_admin','reception','practitioner','doctor'],
    pharmacy_operate: ['super_admin','pharmacy'],
    product_master_write: ['super_admin','pharmacy','production','inventory'],
    production_operate: ['super_admin','production','inventory'],
    quality_operate: ['super_admin','quality'],
    billing_operate: ['super_admin','billing'],
    admin_center: ['super_admin','admin']
  });

  function can(profile, capability) {
    // Operational access is accepted only after the database returns the
    // tenant + department context. A stale frontend role must never become an
    // authorization fallback while a migration or RPC is unavailable.
    if (profile?.access_context_ready !== true) return false;
    const allowed = permissions[capability] || [];
    return rolesOf(profile).grantedRoles.some(role => allowed.includes(role));
  }

  async function getSession() {
    return (await getDb().auth.getSession()).data.session || null;
  }

  async function accountRequest(action) {
    const session = await getSession();
    if (!session?.access_token) throw new Error('กรุณาเข้าสู่ระบบใหม่');
    const response = await fetch('/api/account-access', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify({ action }), signal: AbortSignal.timeout(45000)
    });
    const result = await response.json().catch(() => null);
    if (!response.ok || result?.ok !== true) {
      const messages = {
        ACCOUNT_SESSION_INVALID: 'Session หมดอายุ กรุณาออกจากระบบแล้วเข้าใหม่',
        ACCOUNT_GOVERNANCE_REQUIRED: 'บัญชีนี้ยังไม่มีสิทธิ์จัดการผู้ใช้ของคลินิก',
        ACCOUNT_SERVICE_UNAVAILABLE: 'ตรวจสอบบัญชีไม่สำเร็จ กรุณาลองอีกครั้งหรือติดต่อผู้ดูแล'
      };
      throw new Error(messages[result?.code] || 'ตรวจสอบบัญชีไม่สำเร็จ กรุณาลองอีกครั้ง');
    }
    return result;
  }

  function showAccountStatus(profile, session) {
    const boot = document.getElementById('boot');
    if (!boot) return;
    boot.querySelector('.spinner')?.classList.add('hidden');
    const pending = profile?.account_status === 'pending_approval';
    const title = boot.querySelector('h2');
    if (title) title.textContent = pending ? 'เข้าสู่ระบบแล้ว · รอกำหนดสิทธิ์' : 'ยังเข้าใช้งานคลินิกไม่ได้';
    const message = document.getElementById('boot-error');
    if (message) message.textContent = pending
      ? 'บัญชีพร้อมให้ Super Admin เลือกในศูนย์ควบคุม → ผู้ใช้และสิทธิ์ กรุณารอการกำหนดแผนกก่อนเข้าใช้งาน'
      : 'กรุณาให้ผู้ดูแลตรวจสอบสมาชิกคลินิกและสถานะการใช้งานของบัญชีนี้';
    document.getElementById('account-status-actions')?.remove();
    const panel = document.createElement('div');
    panel.id = 'account-status-actions'; panel.className = 'account-status-actions';
    const email = document.createElement('p'); email.textContent = session?.user?.email || profile?.email || ''; panel.appendChild(email);
    const refresh = document.createElement('button'); refresh.type = 'button'; refresh.className = 'btn'; refresh.textContent = 'ตรวจสอบสิทธิ์อีกครั้ง';
    refresh.addEventListener('click', () => location.reload()); panel.appendChild(refresh);
    const logout = document.createElement('button'); logout.type = 'button'; logout.className = 'btn'; logout.textContent = 'ออกจากระบบ / เปลี่ยนบัญชี';
    logout.addEventListener('click', async () => {
      logout.disabled = true;
      try {
        const result = await getDb().auth.signOut({ scope: 'local' });
        if (result.error) throw result.error;
        location.replace('/login.html');
      } catch { logout.disabled = false; if (message) message.textContent = 'ออกจากระบบไม่สำเร็จ กรุณาลองอีกครั้ง'; }
    });
    panel.appendChild(logout); boot.firstElementChild.appendChild(panel);
  }

  async function getProfile(userId) {
    if (!userId) return null;
    const { data, error } = await getDb()
      .from('profiles')
      .select('id,role,system_role,full_name,email')
      .eq('id', userId)
      .maybeSingle();
    if (error) throw error;
    if (!data) {
      const account = await accountRequest('status');
      if (account.profile?.id !== userId) throw new Error('บัญชีเข้าสู่ระบบเปลี่ยนไป กรุณาโหลดหน้าใหม่');
      // Identity display only. A server response never supplies operational roles.
      return Object.freeze({ id: userId, full_name: account.profile.full_name, email: account.profile.email,
        role: 'viewer', system_role: 'staff', access_context_ready: false, account_status: account.status });
    }

    const access = await getDb().rpc('current_access_context');
    if (access.error) {
      console.warn('Department access migration is not active; using fail-closed UI compatibility context');
      return Object.freeze({ ...data, access_context_ready: false });
    }
    const row = Array.isArray(access.data) ? access.data[0] : access.data;
    if (!row?.clinic_id || !row?.clinic_role) {
      return Object.freeze({ ...data, role: 'viewer', access_context_ready: false });
    }
    const expectedTenant = deploymentConfig().tenant || {};
    const expectedClinicId = String(expectedTenant.expectedClinicId || '').toLowerCase();
    const expectedClinicCode = String(expectedTenant.expectedClinicCode || '').toUpperCase();
    const actualClinicId = String(row.clinic_id || '').toLowerCase();
    const actualClinicCode = String(row.clinic_code || '').toUpperCase();
    if ((expectedClinicId && expectedClinicId !== actualClinicId) || (expectedClinicCode && expectedClinicCode !== actualClinicCode)) {
      console.error('Deployment tenant and database tenant do not match');
      return Object.freeze({
        ...data,
        role: 'viewer',
        clinic_id: row.clinic_id,
        clinic_code: row.clinic_code,
        access_context_ready: false,
        tenant_mismatch: true
      });
    }
    return Object.freeze({
      ...data,
      role: row.clinic_role,
      clinic_role: row.clinic_role,
      clinic_id: row.clinic_id,
      clinic_code: row.clinic_code,
      clinic_name: row.clinic_name,
      system_role: row.system_role || data.system_role,
      access_context_ready: row.ready === true
    });
  }

  window.ChananyaRuntime = Object.freeze({ getDb, getSession, getProfile, accountRequest, showAccountStatus, rolesOf, roleOf, can, permissions });
})();
