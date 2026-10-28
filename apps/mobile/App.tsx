import React, {useEffect, useState} from 'react';
import {Alert, ActivityIndicator, ScrollView, StyleSheet, Text, TextInput, TouchableOpacity, View} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import * as ImagePicker from 'expo-image-picker';
import {Evidence, EvidenceItem, HighlightedMessage, ResultHeader, UrlDetail, UrlObservations} from './ResultPresentation';
import {StatusBar} from 'expo-status-bar';

const API = process.env.EXPO_PUBLIC_API_URL || 'http://10.0.2.2:8000/api';

type Scan = {
  id: string;
  kind: string;
  text: string;
  status: string;
  created: number;
  report_id?: string;
  reviews: {verdict: string; reason: string; created?: number}[];
  result: {
    models?: {kind: string; version: string; prediction: string; effect: string; scope: string; conflict?: string}[];
    model_mode?: string;
    assessment?: string;
    score?: number;
    explanation?: string;
    version?: string;
    error?: string;
    message?: string;
    evidence?: Evidence[];
    url_details?: UrlDetail[];
    next_actions?: string[];
    coverage?: {completed: string[]; failed?: string[]; unavailable: string[]};
  };
};

type UserProfile = {
  id: string;
  email: string;
  role: 'user' | 'analyst' | 'admin';
  mfa_enabled: boolean;
};

type ReportItem = {
  id: string;
  reason: string;
  status: string;
  created: number;
  scan: Scan;
};

type CampaignItem = {
  id: string;
  name: string;
  report_ids: string[];
  reason: string;
};

type AuditItem = {
  id: string;
  actor: string;
  action: string;
  target: string;
  created: number;
};

type TeamUser = {
  id: string;
  email: string;
  role: 'user' | 'analyst' | 'admin';
  mfa_enabled: boolean;
};

type ModelInfo = {
  version: string;
  type: string;
  metrics: null | unknown;
  languages: string[];
  evaluation_status: string;
  models?: {status?: string; enabled?: {version: string}[]};
  live_url_checks: boolean;
};

export default function App() {
  const [token, setToken] = useState('');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState<'overview' | 'scan' | 'history' | 'model' | 'queue' | 'campaigns' | 'team' | 'audit' | 'settings'>('overview');
  const [auth, setAuth] = useState<'login' | 'register' | 'verify' | 'resend' | 'forgot' | 'reset'>('login');
  const [showMfa, setShowMfa] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [actionToken, setActionToken] = useState('');
  const [text, setText] = useState('');
  const [kind, setKind] = useState<'text' | 'url'>('text');
  const [scans, setScans] = useState<Scan[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [search, setSearch] = useState('');
  const [comment, setComment] = useState('');

  // Extended features state
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [activeReport, setActiveReport] = useState<ReportItem | null>(null);
  const [verdict, setVerdict] = useState<'Confirmed scam' | 'Legitimate' | 'Uncertain'>('Confirmed scam');
  const [reviewReason, setReviewReason] = useState('');

  const [campaignData, setCampaignData] = useState<{nodes: {id: string; label: string}[]; edges: {source: string; target: string; reasons: {type: string; value: string}[]}[]; campaigns: CampaignItem[]}>({nodes: [], edges: [], campaigns: []});
  const [campaignName, setCampaignName] = useState('');
  const [campaignReason, setCampaignReason] = useState('');
  const [selectedReportIds, setSelectedReportIds] = useState<string[]>([]);

  const [teamUsers, setTeamUsers] = useState<TeamUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditItem[]>([]);

  // MFA setup & recovery regeneration state in Settings
  const [enrollSecret, setEnrollSecret] = useState('');
  const [enrollOtp, setEnrollOtp] = useState('');
  const [showRegenMfa, setShowRegenMfa] = useState(false);
  const [reauthPassword, setReauthPassword] = useState('');
  const [reauthOtp, setReauthOtp] = useState('');
  const [reauthRecovery, setReauthRecovery] = useState('');

  async function api(path: string, method = 'GET', body?: object | FormData) {
    const headers: Record<string, string> = {
      ...(token ? {Authorization: `Bearer ${token}`} : {}),
    };
    if (body && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(API + path, {
      method,
      headers,
      body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
    });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401 && token) {
        await SecureStore.deleteItemAsync('session');
        setToken('');
        setUser(null);
        setScan(null);
      }
      throw Error(typeof data.detail === 'string' ? data.detail : 'Request failed. Check your input.');
    }
    return data;
  }

  async function run(work: () => Promise<void>) {
    setBusy(true);
    try {
      await work();
    } catch (e) {
      Alert.alert('ScamShield', e instanceof Error ? e.message : 'Network unavailable. Try again.');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    SecureStore.getItemAsync('session').then(t => {
      if (t) setToken(t);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    if (!token) return;
    run(async () => {
      const [u, s] = await Promise.all([api('/me'), api('/scans')]);
      setUser(u);
      setScans(s);
    });
  }, [token]);

  useEffect(() => {
    if (!scan || !['queued', 'processing'].includes(scan.status)) return;
    const timer = setTimeout(
      () =>
        run(async () => {
          const updated = await api('/scans/' + scan.id);
          setScan(updated);
          if (updated.status === 'awaiting_confirmation') setText(updated.text);
        }),
      1800
    );
    return () => clearTimeout(timer);
  }, [scan]);

  // Load page-specific data when tab changes
  async function loadPage(targetPage: typeof page) {
    setPage(targetPage);
    setScan(null);
    setActiveReport(null);
    if (!token) return;

    if (targetPage === 'overview' || targetPage === 'history') {
      run(async () => setScans(await api('/scans')));
    } else if (targetPage === 'model') {
      run(async () => setModelInfo(await api('/model')));
    } else if (targetPage === 'queue') {
      run(async () => setReports(await api('/reports')));
    } else if (targetPage === 'campaigns') {
      run(async () => setCampaignData(await api('/campaigns')));
    } else if (targetPage === 'team') {
      run(async () => setTeamUsers(await api('/admin/users')));
    } else if (targetPage === 'audit') {
      run(async () => setAuditLogs(await api('/admin/audit')));
    } else if (targetPage === 'settings') {
      run(async () => setUser(await api('/me')));
    }
  }

  async function signout() {
    await api('/auth/logout', 'POST');
    await SecureStore.deleteItemAsync('session');
    setToken('');
    setUser(null);
    setScan(null);
    setPage('overview');
  }

  function generateMfaSecret() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let sec = '';
    for (let i = 0; i < 32; i++) {
      sec += chars[Math.floor(Math.random() * chars.length)];
    }
    setEnrollSecret(sec);
    setEnrollOtp('');
  }

  const button = (title: string, onPress: () => void, secondary = false, danger = false) => (
    <TouchableOpacity
      accessibilityRole="button"
      disabled={busy}
      style={[styles.button, secondary && styles.secondary, danger && styles.dangerButton, busy && {opacity: 0.5}]}
      onPress={onPress}>
      <Text style={[styles.buttonText, secondary && {color: '#226b56'}, danger && {color: 'white'}]}>{title}</Text>
    </TouchableOpacity>
  );

  const input = (value: string, setter: (v: string) => void, placeholder: string, secure = false) => (
    <TextInput
      style={styles.input}
      value={value}
      onChangeText={setter}
      placeholder={placeholder}
      placeholderTextColor="#819088"
      secureTextEntry={secure}
      autoCapitalize="none"
    />
  );

  if (loading) {
    return (
      <View style={styles.container}>
        <ActivityIndicator color="#226b56" />
      </View>
    );
  }

  // Navigation tab list based on user role
  const isStaff = user?.role === 'analyst' || user?.role === 'admin';
  const isAdmin = user?.role === 'admin';
  const navTabs: (typeof page)[] = [
    'overview',
    'scan',
    'history',
    'model',
    ...(isStaff ? (['queue', 'campaigns'] as const) : []),
    ...(isAdmin ? (['team', 'audit'] as const) : []),
    'settings',
  ];

  return (
    <View style={styles.container}>
      <StatusBar style="dark" />
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        {/* Header Branding */}
        <View style={styles.topBar}>
          <Text style={styles.brand}>◈ SCAMSHIELD AI</Text>
          {user && (
            <View style={styles.userBadge}>
              <Text style={styles.userRoleText}>{user.role.toUpperCase()}</Text>
            </View>
          )}
        </View>

        {!token ? (
          /* ============================================================
             AUTH / LOGIN / REGISTRATION
             ============================================================ */
          <>
            <Text style={styles.eyebrow}>A LITTLE CAUTION. A LOT OF CLARITY.</Text>
            <Text style={styles.title}>Pause. Check.{'\n'}Stay ahead.</Text>
            <Text style={styles.description}>Evidence-based message checks, in your pocket.</Text>

            <View style={styles.card}>
              <Text style={styles.heading}>
                {
                  (
                    {
                      login: 'Welcome back',
                      register: 'Create your account',
                      verify: 'Verify email',
                      resend: 'Resend verification',
                      forgot: 'Reset password',
                      reset: 'Set a new password',
                    } as Record<string, string>
                  )[auth]
                }
              </Text>

              {['login', 'register', 'forgot', 'resend'].includes(auth) && input(email, setEmail, 'Email address')}
              {['login', 'register', 'reset'].includes(auth) && input(password, setPassword, 'Password (10+ characters)', true)}

              {/* MFA Fields with clean optional toggle */}
              {auth === 'login' &&
                (!showMfa ? (
                  <TouchableOpacity onPress={() => setShowMfa(true)} style={{marginVertical: 4}}>
                    <Text style={[styles.link, {paddingVertical: 4}]}>+ Have an authenticator / recovery code?</Text>
                  </TouchableOpacity>
                ) : (
                  <>
                    {input(otp, setOtp, 'Authenticator code (6 digits)')}
                    {input(recoveryCode, setRecoveryCode, 'Or a single-use recovery code')}
                    <TouchableOpacity onPress={() => setShowMfa(false)} style={{marginVertical: 2}}>
                      <Text style={[styles.link, {paddingVertical: 2, color: '#82917e'}]}>- Hide authenticator fields</Text>
                    </TouchableOpacity>
                  </>
                ))}

              {['verify', 'reset'].includes(auth) && input(actionToken, setActionToken, 'Email token')}

              {button('Continue →', () =>
                run(async () => {
                  const d = await api(
                    '/auth/' + auth,
                    'POST',
                    auth === 'login' || auth === 'register'
                      ? {email, password, otp, recovery_code: recoveryCode}
                      : ['forgot', 'resend'].includes(auth)
                      ? {email}
                      : {token: actionToken, password}
                  );
                  if (auth === 'login') {
                    await SecureStore.setItemAsync('session', d.token);
                    setToken(d.token);
                    setPassword('');
                    setRecoveryCode('');
                    setOtp('');
                  } else {
                    Alert.alert(
                      'ScamShield',
                      d.message + (d.development_token ? '\nDevelopment token: ' + d.development_token : '')
                    );
                    if (d.development_token) setActionToken(d.development_token);
                    setAuth(['register', 'resend'].includes(auth) ? 'verify' : auth === 'forgot' ? 'reset' : 'login');
                  }
                })
              )}

              {/* One-tap Demo Login Button */}
              {auth === 'login' &&
                button(
                  'Try Demo — Fill & Sign In ↗',
                  () =>
                    run(async () => {
                      setEmail('demo@scamshield.test');
                      setPassword('ScamShieldDemo123!');
                      setOtp('');
                      setRecoveryCode('');
                      const d = await api('/auth/login', 'POST', {
                        email: 'demo@scamshield.test',
                        password: 'ScamShieldDemo123!',
                        otp: '',
                        recovery_code: '',
                      });
                      await SecureStore.setItemAsync('session', d.token);
                      setToken(d.token);
                      setPassword('');
                    }),
                  true
                )}

              {(['login', 'register', 'verify', 'resend', 'forgot', 'reset'] as const)
                .filter(a => a !== auth)
                .map(a => (
                  <TouchableOpacity key={a} onPress={() => setAuth(a)}>
                    <Text style={styles.link}>
                      {
                        ({
                          login: 'Sign in',
                          register: 'Create account',
                          verify: 'Verify email',
                          resend: 'Resend verification',
                          forgot: 'Forgot password?',
                          reset: 'Have a reset token?',
                        })[a]
                      }
                    </Text>
                  </TouchableOpacity>
                ))}
            </View>
          </>
        ) : (
          /* ============================================================
             AUTHENTICATED APP (WITH FULL WEB PARITY)
             ============================================================ */
          <>
            {/* Horizontal Scrollable Nav Tabs */}
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.navBar} contentContainerStyle={styles.navScroll}>
              {navTabs.map(t => (
                <TouchableOpacity key={t} style={[styles.navTab, page === t && styles.navTabActive]} onPress={() => loadPage(t)}>
                  <Text style={[styles.navTabText, page === t && styles.navTabTextActive]}>{t.toUpperCase()}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>

            {/* Active Scan Inspector (if viewing a specific scan) */}
            {scan ? (
              <View style={styles.card}>
                <ResultHeader assessment={scan.result.assessment} status={scan.status} />
                {['queued', 'processing'].includes(scan.status) && <ActivityIndicator color="#226b56" style={{marginVertical: 12}} />}
                <Text style={styles.description}>{scan.result.explanation || scan.result.error || scan.result.message}</Text>
                {scan.result.score !== undefined && (
                  <Text style={styles.description}>Indicator score {scan.result.score}/100 · Not a probability</Text>
                )}

                {['awaiting_confirmation', 'partially_completed'].includes(scan.status) ? (
                  <>
                    <Text style={styles.heading}>Review or enter the message</Text>
                    <TextInput style={[styles.input, styles.textarea]} multiline value={text} onChangeText={setText} />
                    {button('Confirm text & analyze', () =>
                      run(async () => setScan(await api('/scans/' + scan.id + '/confirm', 'POST', {kind: 'text', text})))
                    )}
                  </>
                ) : (
                  <>
                    <HighlightedMessage text={scan.text} evidence={scan.result.evidence || []} />
                    <UrlObservations details={scan.result.url_details || []} />
                    {scan.result.model_mode && <Text style={styles.description}>Model mode: {scan.result.model_mode}</Text>}
                    {scan.result.models?.map((m, i) => (
                      <View key={i} style={styles.evidence}>
                        <Text style={styles.heading}>
                          {m.kind}: {m.prediction}
                        </Text>
                        <Text style={styles.description}>
                          {m.version}
                          {'\n'}
                          {m.effect}
                          {'\n'}
                          {m.conflict || m.scope}
                          {'\n'}Separate from rules evidence. Spam/ham does not establish fraud or safety.
                        </Text>
                      </View>
                    ))}
                    {scan.result.evidence?.map((e, i) => (
                      <EvidenceItem key={i} item={e} />
                    ))}
                    {scan.result.next_actions?.map(a => (
                      <Text key={a} style={styles.description}>
                        • {a}
                      </Text>
                    ))}
                    <Text style={styles.description}>
                      Failed: {scan.result.coverage?.failed?.join(', ') || 'None recorded'}
                      {'\n'}Unavailable: {scan.result.coverage?.unavailable?.join(', ')}
                    </Text>
                    <Text style={styles.description}>{scan.result.version}</Text>

                    {scan.reviews?.map((r, i) => (
                      <View style={styles.evidence} key={i}>
                        <Text style={styles.heading}>Analyst Verdict: {r.verdict}</Text>
                        <Text style={styles.description}>{r.reason}</Text>
                      </View>
                    ))}

                    {scan.status === 'completed' && (
                      <>
                        {input(comment, setComment, 'Feedback / reason for review')}
                        {button(
                          'Send feedback',
                          () =>
                            run(async () => {
                              const d = await api('/scans/' + scan.id + '/feedback', 'POST', {reason: comment});
                              Alert.alert('Saved', d.message);
                              setComment('');
                            }),
                          true
                        )}
                        {!scan.report_id &&
                          button(
                            'Submit for analyst review',
                            () =>
                              Alert.alert('Share this scan?', 'Authorized analysts will be able to view this scan.', [
                                {text: 'Cancel', style: 'cancel'},
                                {
                                  text: 'Submit',
                                  onPress: () =>
                                    run(async () => {
                                      await api('/scans/' + scan.id + '/report', 'POST', {reason: comment});
                                      setScan(await api('/scans/' + scan.id));
                                      Alert.alert('Submitted', 'Your report is in the review queue.');
                                    }),
                                },
                              ]),
                            true
                          )}
                      </>
                    )}
                    {button(
                      'Delete scan',
                      () =>
                        Alert.alert('Delete scan?', 'This removes the scan and screenshot.', [
                          {text: 'Cancel', style: 'cancel'},
                          {
                            text: 'Delete',
                            style: 'destructive',
                            onPress: () =>
                              run(async () => {
                                await api('/scans/' + scan.id, 'DELETE');
                                setScan(null);
                                setScans(await api('/scans'));
                              }),
                          },
                        ]),
                      true,
                      true
                    )}
                  </>
                )}
                {button('Back', () => setScan(null), true)}
              </View>
            ) : page === 'overview' ? (
              /* ============================================================
                 PAGE 1: OVERVIEW (METRICS & QUICK SCAN)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>YOUR DIGITAL SAFETY, IN FOCUS</Text>
                <Text style={styles.title}>A clearer view{'\n'}of your safety.</Text>
                <Text style={styles.description}>Check the unexpected. Understand the evidence. Take your next step with confidence.</Text>

                {/* 4 Stat Metric Cards */}
                <View style={styles.statsGrid}>
                  <View style={styles.statBox}>
                    <Text style={styles.statLabel}>TOTAL SCANS</Text>
                    <Text style={styles.statNumber}>{scans.length.toString().padStart(2, '0')}</Text>
                    <Text style={styles.statSub}>Your latest scans</Text>
                  </View>
                  <View style={styles.statBox}>
                    <Text style={styles.statLabel}>HIGH RISK</Text>
                    <Text style={[styles.statNumber, {color: '#b24a40'}]}>
                      {scans.filter(s => s.result.assessment === 'High').length.toString().padStart(2, '0')}
                    </Text>
                    <Text style={styles.statSub}>Worth closer look</Text>
                  </View>
                  <View style={styles.statBox}>
                    <Text style={styles.statLabel}>COMPLETED</Text>
                    <Text style={[styles.statNumber, {color: '#226b56'}]}>
                      {scans.filter(s => s.status === 'completed').length.toString().padStart(2, '0')}
                    </Text>
                    <Text style={styles.statSub}>Evidence ready</Text>
                  </View>
                  <View style={styles.statBox}>
                    <Text style={styles.statLabel}>IN PROGRESS</Text>
                    <Text style={[styles.statNumber, {color: '#a07c31'}]}>
                      {scans.filter(s => ['queued', 'processing'].includes(s.status)).length.toString().padStart(2, '0')}
                    </Text>
                    <Text style={styles.statSub}>Queued or processing</Text>
                  </View>
                </View>

                {/* Quick actions card */}
                <View style={styles.card}>
                  <Text style={styles.heading}>What would you like to check?</Text>
                  <Text style={styles.description}>One suspicious input. A better-informed next step.</Text>
                  <View style={{flexDirection: 'row', gap: 10, marginTop: 4}}>
                    <TouchableOpacity
                      style={[styles.smallActionBtn, {flex: 1}]}
                      onPress={() => {
                        setKind('text');
                        setPage('scan');
                      }}>
                      <Text style={styles.smallActionIcon}>▤</Text>
                      <Text style={styles.smallActionTitle}>Message</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.smallActionBtn, {flex: 1}]}
                      onPress={() => {
                        setKind('url');
                        setPage('scan');
                      }}>
                      <Text style={styles.smallActionIcon}>↗</Text>
                      <Text style={styles.smallActionTitle}>Check Link</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.smallActionBtn, {flex: 1}]}
                      onPress={() => {
                        setPage('scan');
                      }}>
                      <Text style={styles.smallActionIcon}>▧</Text>
                      <Text style={styles.smallActionTitle}>Screenshot</Text>
                    </TouchableOpacity>
                  </View>
                </View>

                {/* Recent Scans snippet */}
                <View style={styles.card}>
                  <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8}}>
                    <Text style={styles.heading}>Recent findings</Text>
                    <TouchableOpacity onPress={() => setPage('history')}>
                      <Text style={styles.link}>View all ↗</Text>
                    </TouchableOpacity>
                  </View>
                  {scans.slice(0, 3).map(s => (
                    <TouchableOpacity
                      key={s.id}
                      style={styles.recentItem}
                      onPress={() =>
                        run(async () => {
                          const fresh = await api('/scans/' + s.id);
                          setScan(fresh);
                          setText(fresh.text);
                        })
                      }>
                      <View style={{flex: 1}}>
                        <Text numberOfLines={1} style={styles.recentText}>
                          {s.text || 'Screenshot upload'}
                        </Text>
                        <Text style={styles.recentSub}>
                          {s.kind.toUpperCase()} · {new Date(s.created * 1000).toLocaleDateString()}
                        </Text>
                      </View>
                      <Text style={[styles.badgeText, s.result.assessment === 'High' ? styles.badgeHigh : styles.badgeNormal]}>
                        {s.result.assessment || s.status}
                      </Text>
                    </TouchableOpacity>
                  ))}
                  {scans.length === 0 && <Text style={styles.description}>No scans yet. Start by checking a message or link.</Text>}
                </View>

                {/* Safety Tips */}
                <View style={styles.notice}>
                  <Text style={styles.heading}>A safer next step</Text>
                  <Text style={styles.tipItem}>• 01 Keep one-time codes private from callers and chat.</Text>
                  <Text style={styles.tipItem}>• 02 Go directly to the official bank/service app or verified contact.</Text>
                  <Text style={styles.tipItem}>• 03 Slow down urgency — threats of account closure are classic flags.</Text>
                </View>
              </>
            ) : page === 'scan' ? (
              /* ============================================================
                 PAGE 2: NEW SCAN (TEXT, URL, SCREENSHOT)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>TRUST YOUR INSTINCT. CHECK THE EVIDENCE.</Text>
                <Text style={styles.title}>Something feel{'\n'}suspicious?</Text>
                <Text style={styles.description}>Choose an input. We’ll show the evidence behind the assessment.</Text>

                <View style={styles.card}>
                  <View style={styles.tabToggle}>
                    <TouchableOpacity
                      style={[styles.toggleBtn, kind === 'text' && styles.toggleBtnActive]}
                      onPress={() => setKind('text')}>
                      <Text style={[styles.toggleText, kind === 'text' && styles.toggleTextActive]}>MESSAGE TEXT</Text>
                    </TouchableOpacity>
                    <TouchableOpacity
                      style={[styles.toggleBtn, kind === 'url' && styles.toggleBtnActive]}
                      onPress={() => setKind('url')}>
                      <Text style={[styles.toggleText, kind === 'url' && styles.toggleTextActive]}>URL LINK</Text>
                    </TouchableOpacity>
                  </View>

                  <TextInput
                    style={[styles.input, styles.textarea]}
                    multiline
                    value={text}
                    onChangeText={setText}
                    placeholder={kind === 'url' ? 'https://example.com/login' : 'Paste the suspicious SMS, WhatsApp message, or email text…'}
                    maxLength={20000}
                  />

                  {button('Analyze ' + (kind === 'url' ? 'link' : 'message') + ' ↗', () =>
                    run(async () => {
                      if (!text.trim()) {
                        Alert.alert('ScamShield', 'Please enter text or a URL to analyze.');
                        return;
                      }
                      const s = await api('/scans', 'POST', {kind, text});
                      setScan(s);
                      setText(s.text);
                    })
                  )}

                  {button(
                    'Upload screenshot',
                    () =>
                      run(async () => {
                        const result = await ImagePicker.launchImageLibraryAsync({mediaTypes: ['images'], quality: 1});
                        if (result.canceled) return;
                        const a = result.assets[0];
                        const form = new FormData();
                        form.append('file', {
                          uri: a.uri,
                          name: a.fileName || 'screenshot.jpg',
                          type: a.mimeType || 'image/jpeg',
                        } as unknown as Blob);
                        const s = await api('/scans/screenshot', 'POST', form);
                        setScan(s);
                        setText('');
                      }),
                    true
                  )}
                  <Text style={styles.fine}>No links are opened during analysis. OCR text can be corrected. PNG/JPEG up to 5 MB.</Text>
                </View>
              </>
            ) : page === 'history' ? (
              /* ============================================================
                 PAGE 3: HISTORY & SEARCH
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>YOUR RECORDS</Text>
                <Text style={styles.title}>Your findings.</Text>
                <Text style={styles.description}>A private record of what you checked and what you found.</Text>

                <TextInput
                  style={styles.input}
                  placeholder="Search your scans by message, result, or type…"
                  placeholderTextColor="#819088"
                  value={search}
                  onChangeText={setSearch}
                />

                {scans.length === 0 && <Text style={styles.description}>No scans yet. Start with a message or screenshot.</Text>}

                {scans
                  .filter(s => (s.text + ' ' + s.result.assessment + ' ' + s.kind).toLowerCase().includes(search.toLowerCase()))
                  .map(s => (
                    <TouchableOpacity
                      key={s.id}
                      style={styles.card}
                      onPress={() =>
                        run(async () => {
                          const fresh = await api('/scans/' + s.id);
                          setScan(fresh);
                          setText(fresh.text);
                        })
                      }>
                      <View style={{flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4}}>
                        <Text style={styles.eyebrow}>
                          {s.kind.toUpperCase()} · {new Date(s.created * 1000).toLocaleDateString()}
                        </Text>
                        <Text style={[styles.badgeText, s.result.assessment === 'High' ? styles.badgeHigh : styles.badgeNormal]}>
                          {s.result.assessment || s.status}
                        </Text>
                      </View>
                      <Text numberOfLines={2} style={styles.heading}>
                        {s.text || 'Screenshot upload'}
                      </Text>
                      <Text style={styles.link}>Inspect full evidence ↗</Text>
                    </TouchableOpacity>
                  ))}
              </>
            ) : page === 'model' ? (
              /* ============================================================
                 PAGE 4: DETECTION MODEL & BENCHMARKS
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>SYSTEM TRANSPARENCY</Text>
                <Text style={styles.title}>Detection Model.</Text>
                <Text style={styles.description}>Transparent versioning, honest coverage, and room to improve.</Text>

                <View style={styles.card}>
                  <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10}}>
                    <Text style={styles.heading}>{modelInfo?.type || 'Versioned rules baseline'}</Text>
                    <Text style={styles.badgeText}>{modelInfo?.version || 'v1.2.0'}</Text>
                  </View>
                  <Text style={styles.description}>
                    Current assessments use deterministic text patterns and static URL features.
                    {'\n'}Status: {modelInfo?.models?.status || 'No optional benchmark model loaded'}.
                    {'\n'}Active models: {modelInfo?.models?.enabled?.map(m => m.version).join(', ') || 'Rules only'}.
                  </Text>
                  <View style={styles.notice}>
                    <Text style={styles.heading}>Supported Language Patterns</Text>
                    <Text style={styles.description}>{modelInfo?.languages.join(' · ') || 'English · Sinhala · Tamil · Singlish'}</Text>
                  </View>
                  <Text style={styles.fine}>{modelInfo?.evaluation_status || 'Local-language rules remain experimental.'}</Text>
                </View>

                <View style={styles.card}>
                  <Text style={styles.heading}>Coverage at a glance</Text>
                  <View style={styles.coverageRow}>
                    <Text style={styles.checkIcon}>✓</Text>
                    <View style={{flex: 1}}>
                      <Text style={styles.coverageTitle}>Text pattern evidence</Text>
                      <Text style={styles.description}>Exact keyword spans and versioned indicator weights.</Text>
                    </View>
                  </View>
                  <View style={styles.coverageRow}>
                    <Text style={styles.checkIcon}>✓</Text>
                    <View style={{flex: 1}}>
                      <Text style={styles.coverageTitle}>Static URL structure</Text>
                      <Text style={styles.description}>Hostnames, punycode/encoding, IP hosts, and PSL domains.</Text>
                    </View>
                  </View>
                  <View style={styles.coverageRow}>
                    <Text style={[styles.checkIcon, {color: '#82917e'}]}>—</Text>
                    <View style={{flex: 1}}>
                      <Text style={styles.coverageTitle}>Live reputation checks</Text>
                      <Text style={styles.description}>Unavailable. User URLs are never fetched over the internet.</Text>
                    </View>
                  </View>
                </View>
              </>
            ) : page === 'queue' ? (
              /* ============================================================
                 PAGE 5: ANALYST REVIEW QUEUE (STAFF / ADMIN)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>ANALYST INTELLIGENCE</Text>
                <Text style={styles.title}>Review Queue.</Text>
                <Text style={styles.description}>Human judgment grounded in evidence. Decisions stay separate from predictions.</Text>

                {activeReport ? (
                  <View style={styles.card}>
                    <Text style={styles.heading}>Reviewing Report: {activeReport.id.slice(0, 8)}</Text>
                    <Text style={styles.description}>User Reason: {activeReport.reason || 'None provided'}</Text>
                    <Text style={styles.heading}>Message Content:</Text>
                    <Text style={styles.messageBox}>{activeReport.scan.text || 'Screenshot upload'}</Text>

                    <Text style={styles.heading}>Analyst Verdict:</Text>
                    <View style={{flexDirection: 'row', gap: 8, marginVertical: 8}}>
                      {(['Confirmed scam', 'Legitimate', 'Uncertain'] as const).map(v => (
                        <TouchableOpacity
                          key={v}
                          style={[styles.smallActionBtn, verdict === v && styles.smallActionBtnActive, {flex: 1}]}
                          onPress={() => setVerdict(v)}>
                          <Text style={[styles.smallActionTitle, verdict === v && {color: 'white'}]}>{v}</Text>
                        </TouchableOpacity>
                      ))}
                    </View>

                    {input(reviewReason, setReviewReason, 'Analyst notes & rationale (min 3 characters)')}

                    {button('Submit Decision ↗', () =>
                      run(async () => {
                        if (!reviewReason.trim()) {
                          Alert.alert('ScamShield', 'Please provide a reason for this decision.');
                          return;
                        }
                        await api('/reports/' + activeReport.id + '/decision', 'POST', {
                          verdict,
                          reason: reviewReason,
                        });
                        Alert.alert('Success', 'Review decision recorded.');
                        setActiveReport(null);
                        setReviewReason('');
                        setReports(await api('/reports'));
                      })
                    )}
                    {button('Cancel', () => setActiveReport(null), true)}
                  </View>
                ) : (
                  <>
                    <View style={styles.badgeRow}>
                      <Text style={styles.badgeText}>
                        {reports.filter(r => r.status === 'pending').length} Pending Review
                      </Text>
                    </View>
                    {reports.length === 0 && <Text style={styles.description}>The desk is clear. User-submitted reports appear here.</Text>}
                    {reports.map(r => (
                      <TouchableOpacity key={r.id} style={styles.card} onPress={() => setActiveReport(r)}>
                        <View style={{flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6}}>
                          <Text style={styles.eyebrow}>{new Date(r.created * 1000).toLocaleDateString()}</Text>
                          <Text style={[styles.badgeText, r.status === 'pending' ? styles.badgePending : styles.badgeNormal]}>
                            {r.status.toUpperCase()}
                          </Text>
                        </View>
                        <Text numberOfLines={2} style={styles.heading}>
                          {r.scan.text || 'Screenshot upload'}
                        </Text>
                        <Text style={styles.description}>Reason: {r.reason}</Text>
                        <Text style={styles.link}>Open review desk ↗</Text>
                      </TouchableOpacity>
                    ))}
                  </>
                )}
              </>
            ) : page === 'campaigns' ? (
              /* ============================================================
                 PAGE 6: FRAUD CAMPAIGNS GRAPH & GROUPINGS (STAFF / ADMIN)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>ANALYST INTELLIGENCE</Text>
                <Text style={styles.title}>Campaign Graph.</Text>
                <Text style={styles.description}>Shared entities suggest relationships between suspicious reports.</Text>

                {/* Candidate links */}
                <View style={styles.card}>
                  <Text style={styles.heading}>Candidate Links ({campaignData.edges.length})</Text>
                  {campaignData.edges.length === 0 ? (
                    <Text style={styles.description}>No shared phone numbers or domains identified across reports yet.</Text>
                  ) : (
                    campaignData.edges.map((e, idx) => (
                      <View key={idx} style={styles.evidence}>
                        <Text style={styles.heading}>
                          {e.source.slice(0, 8)} ↔ {e.target.slice(0, 8)}
                        </Text>
                        <Text style={styles.description}>
                          Shared signals: {e.reasons.map(r => r.type + ': ' + r.value).join(', ')}
                        </Text>
                      </View>
                    ))
                  )}
                </View>

                {/* Reviewed Campaigns */}
                <View style={styles.card}>
                  <Text style={styles.heading}>Reviewed Campaigns ({campaignData.campaigns.length})</Text>
                  {campaignData.campaigns.length === 0 ? (
                    <Text style={styles.description}>No grouped campaigns created yet.</Text>
                  ) : (
                    campaignData.campaigns.map(c => (
                      <View key={c.id} style={styles.evidence}>
                        <Text style={styles.heading}>{c.name}</Text>
                        <Text style={styles.description}>{c.reason}</Text>
                        <Text style={styles.fine}>{c.report_ids.length} linked reports</Text>
                        {button(
                          'Dissolve Campaign',
                          () =>
                            Alert.alert('Dissolve Campaign?', 'This preserves the individual reports.', [
                              {text: 'Cancel', style: 'cancel'},
                              {
                                text: 'Dissolve',
                                style: 'destructive',
                                onPress: () =>
                                  run(async () => {
                                    await api('/campaigns/' + c.id, 'DELETE');
                                    setCampaignData(await api('/campaigns'));
                                  }),
                              },
                            ]),
                          true,
                          true
                        )}
                      </View>
                    ))
                  )}
                </View>

                {/* Create Campaign form */}
                {campaignData.nodes.length >= 2 && (
                  <View style={styles.card}>
                    <Text style={styles.heading}>Create Reviewed Campaign</Text>
                    {input(campaignName, setCampaignName, 'Campaign name (e.g. Bank SMS Wave)')}
                    {input(campaignReason, setCampaignReason, 'Reason for grouping (min 3 chars)')}
                    <Text style={styles.fine}>Tap to select 2 or more reports to group:</Text>
                    <View style={{marginVertical: 8, gap: 6}}>
                      {campaignData.nodes.map(n => {
                        const isSelected = selectedReportIds.includes(n.id);
                        return (
                          <TouchableOpacity
                            key={n.id}
                            style={[styles.smallActionBtn, isSelected && styles.smallActionBtnActive]}
                            onPress={() => {
                              setSelectedReportIds(prev =>
                                prev.includes(n.id) ? prev.filter(x => x !== n.id) : [...prev, n.id]
                              );
                            }}>
                            <Text style={[styles.smallActionTitle, isSelected && {color: 'white'}]}>
                              {isSelected ? '✓ ' : '+ '}
                              {n.id.slice(0, 8)} · {n.label.slice(0, 30)}
                            </Text>
                          </TouchableOpacity>
                        );
                      })}
                    </View>
                    {button('Save Campaign ↗', () =>
                      run(async () => {
                        if (selectedReportIds.length < 2) {
                          Alert.alert('ScamShield', 'Please select at least 2 reports.');
                          return;
                        }
                        await api('/campaigns', 'POST', {
                          name: campaignName,
                          reason: campaignReason,
                          report_ids: selectedReportIds,
                        });
                        Alert.alert('Saved', 'Reviewed campaign created.');
                        setCampaignName('');
                        setCampaignReason('');
                        setSelectedReportIds([]);
                        setCampaignData(await api('/campaigns'));
                      })
                    )}
                  </View>
                )}
              </>
            ) : page === 'team' ? (
              /* ============================================================
                 PAGE 7: TEAM & ROLES (ADMIN ONLY)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>ADMINISTRATION</Text>
                <Text style={styles.title}>Team & Roles.</Text>
                <Text style={styles.description}>Staff accounts require an enrolled authenticator. Role changes revoke active sessions.</Text>

                <View style={styles.card}>
                  <Text style={styles.heading}>User Accounts ({teamUsers.length})</Text>
                  {teamUsers.map(u => (
                    <View key={u.id} style={styles.evidence}>
                      <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'}}>
                        <Text style={styles.heading}>{u.email}</Text>
                        <Text style={[styles.badgeText, u.role === 'admin' ? styles.badgeHigh : styles.badgeNormal]}>
                          {u.role.toUpperCase()}
                        </Text>
                      </View>
                      <Text style={styles.description}>MFA Status: {u.mfa_enabled ? 'Enrolled' : 'Not Enrolled'}</Text>
                      {u.id !== user?.id && (
                        <View style={{flexDirection: 'row', gap: 6, marginTop: 8}}>
                          {(['user', 'analyst', 'admin'] as const).map(r => (
                            <TouchableOpacity
                              key={r}
                              style={[styles.smallActionBtn, u.role === r && styles.smallActionBtnActive, {flex: 1}]}
                              onPress={() =>
                                Alert.alert('Update Role', `Change ${u.email} to ${r}?`, [
                                  {text: 'Cancel', style: 'cancel'},
                                  {
                                    text: 'Confirm',
                                    onPress: () =>
                                      run(async () => {
                                        await api('/admin/users/' + u.id + '/role', 'PUT', {role: r});
                                        Alert.alert('Success', 'User role updated.');
                                        setTeamUsers(await api('/admin/users'));
                                      }),
                                  },
                                ])
                              }>
                              <Text style={[styles.smallActionTitle, u.role === r && {color: 'white'}]}>{r}</Text>
                            </TouchableOpacity>
                          ))}
                        </View>
                      )}
                    </View>
                  ))}
                </View>
              </>
            ) : page === 'audit' ? (
              /* ============================================================
                 PAGE 8: AUDIT HISTORY (ADMIN ONLY)
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>ADMINISTRATION</Text>
                <Text style={styles.title}>Audit History.</Text>
                <Text style={styles.description}>Sensitive actions leave a permanent record. Message content is excluded.</Text>

                <View style={styles.card}>
                  <Text style={styles.heading}>Latest Security Events ({auditLogs.length})</Text>
                  {auditLogs.length === 0 && <Text style={styles.description}>No audit events recorded yet.</Text>}
                  {auditLogs.map(a => (
                    <View key={a.id} style={styles.evidence}>
                      <View style={{flexDirection: 'row', justifyContent: 'space-between'}}>
                        <Text style={styles.heading}>{a.action}</Text>
                        <Text style={styles.fine}>{new Date(a.created * 1000).toLocaleTimeString()}</Text>
                      </View>
                      <Text style={styles.description}>
                        Actor: {a.actor.slice(0, 12)}
                        {'\n'}Target: {a.target.slice(0, 12)}
                        {'\n'}Date: {new Date(a.created * 1000).toLocaleDateString()}
                      </Text>
                    </View>
                  ))}
                </View>
              </>
            ) : (
              /* ============================================================
                 PAGE 9: SETTINGS & ACCOUNT & MFA
                 ============================================================ */
              <>
                <Text style={styles.eyebrow}>YOUR PREFERENCES</Text>
                <Text style={styles.title}>Account & Privacy.</Text>
                <Text style={styles.description}>Private by default, with clear choices over your data.</Text>

                <View style={styles.card}>
                  <Text style={styles.heading}>Account details</Text>
                  <Text style={styles.description}>
                    Email: {user?.email}
                    {'\n'}Role: {user?.role.toUpperCase()}
                    {'\n'}MFA: {user?.mfa_enabled ? 'Enrolled ✓' : 'Not Enrolled'}
                  </Text>

                  {/* Authenticator / MFA Enrollment */}
                  <Text style={[styles.heading, {marginTop: 14}]}>Two-Factor Authenticator (TOTP)</Text>
                  {user?.mfa_enabled ? (
                    <>
                      <Text style={styles.description}>MFA is active on your account.</Text>
                      {showRegenMfa ? (
                        <View style={styles.mfaEnrollBox}>
                          <Text style={styles.fine}>Reauthenticate to regenerate recovery codes (revokes active sessions):</Text>
                          {input(reauthPassword, setReauthPassword, 'Current password (10+ characters)', true)}
                          {input(reauthOtp, setReauthOtp, 'Authenticator code (6 digits)')}
                          {input(reauthRecovery, setReauthRecovery, 'Or an unused recovery code')}
                          {button('Confirm & Regenerate Codes', () =>
                            run(async () => {
                              const res = await api('/auth/mfa/recovery-codes', 'POST', {
                                password: reauthPassword,
                                otp: reauthOtp,
                                recovery_code: reauthRecovery,
                              });
                              setShowRegenMfa(false);
                              setReauthPassword('');
                              setReauthOtp('');
                              setReauthRecovery('');
                              Alert.alert(
                                'Save Your New Recovery Codes',
                                (res.recovery_codes?.join('\n') || '') + '\n\n' + (res.message || 'All sessions were revoked; please sign in again.')
                              );
                              await SecureStore.deleteItemAsync('session');
                              setToken('');
                              setUser(null);
                              setScan(null);
                            })
                          )}
                          {button('Cancel', () => setShowRegenMfa(false), true)}
                        </View>
                      ) : (
                        button('Regenerate Recovery Codes', () => setShowRegenMfa(true), true)
                      )}
                    </>
                  ) : enrollSecret ? (
                    <View style={styles.mfaEnrollBox}>
                      <Text style={styles.fine}>Add this secret key into Google Authenticator or 1Password:</Text>
                      <Text style={styles.secretKeyText} selectable>
                        {enrollSecret}
                      </Text>
                      {input(enrollOtp, setEnrollOtp, 'Enter 6-digit code from authenticator')}
                      {button('Verify & Enable MFA', () =>
                        run(async () => {
                          const res = await api('/auth/mfa', 'POST', {secret: enrollSecret, otp: enrollOtp});
                          Alert.alert('MFA Enrolled', 'Save your recovery codes:\n\n' + res.recovery_codes?.join('\n'));
                          setEnrollSecret('');
                          setUser(await api('/me'));
                        })
                      )}
                      {button('Cancel', () => setEnrollSecret(''), true)}
                    </View>
                  ) : (
                    button('Set up authenticator ↗', () => generateMfaSecret(), true)
                  )}
                </View>

                <View style={styles.card}>
                  <Text style={styles.heading}>Data & Privacy</Text>
                  <Text style={styles.description}>
                    Scans belong to your account. Analysts see only scans you submit for review. Default server retention is 90 days.
                  </Text>
                  {button('Sign out', () => run(signout), true)}
                  {button(
                    'Delete account & scans',
                    () =>
                      Alert.alert('Delete your account?', 'All scans and sessions will be removed permanently.', [
                        {text: 'Cancel', style: 'cancel'},
                        {
                          text: 'Delete',
                          style: 'destructive',
                          onPress: () =>
                            run(async () => {
                              await api('/me', 'DELETE');
                              await SecureStore.deleteItemAsync('session');
                              setToken('');
                              setUser(null);
                              setScans([]);
                            }),
                        },
                      ]),
                    true,
                    true
                  )}
                </View>
              </>
            )}
          </>
        )}

        {busy && <ActivityIndicator style={{margin: 15}} color="#226b56" />}
        <Text style={styles.footer}>
          Indicator scores are not probabilities.{'\n'}Rules baseline · multilingual validation pending.
        </Text>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#f5f6f3'},
  content: {padding: 20, paddingTop: 54, paddingBottom: 40},
  topBar: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18},
  brand: {fontSize: 16, fontWeight: '800', color: '#214b38'},
  userBadge: {backgroundColor: '#edf3e9', paddingHorizontal: 9, paddingVertical: 4, borderRadius: 6},
  userRoleText: {fontSize: 10, fontWeight: '700', color: '#226b56', letterSpacing: 0.5},
  eyebrow: {fontSize: 10, letterSpacing: 1.5, color: '#6c8271', marginTop: 10, marginBottom: 8},
  title: {fontSize: 32, fontWeight: '700', letterSpacing: -1.2, color: '#193f31', marginBottom: 10},
  heading: {fontSize: 15, fontWeight: '600', color: '#264a37', marginBottom: 8},
  description: {fontSize: 13, lineHeight: 20, color: '#77867b', marginBottom: 10},
  fine: {fontSize: 11, lineHeight: 17, color: '#88988c', marginVertical: 6},
  card: {backgroundColor: 'white', padding: 20, borderRadius: 14, marginVertical: 10, borderWidth: 1, borderColor: '#e3e9df'},
  input: {borderWidth: 1, borderColor: '#dce5d8', padding: 13, borderRadius: 8, marginVertical: 6, color: '#263f2f', backgroundColor: '#fafbf9'},
  textarea: {height: 140, textAlignVertical: 'top'},
  button: {backgroundColor: '#226b56', padding: 15, borderRadius: 8, marginTop: 10, alignItems: 'center'},
  buttonText: {color: 'white', fontWeight: '600', fontSize: 13},
  secondary: {backgroundColor: '#edf3e9'},
  dangerButton: {backgroundColor: '#b24a40'},
  link: {color: '#34724d', fontSize: 12, paddingVertical: 10, fontWeight: '600'},
  navBar: {marginVertical: 10, maxHeight: 42},
  navScroll: {flexDirection: 'row', gap: 6, alignItems: 'center'},
  navTab: {paddingHorizontal: 13, paddingVertical: 8, borderRadius: 8, backgroundColor: '#edf3e9'},
  navTabActive: {backgroundColor: '#226b56'},
  navTabText: {fontSize: 11, fontWeight: '700', color: '#385e45', letterSpacing: 0.5},
  navTabTextActive: {color: 'white'},
  statsGrid: {flexDirection: 'row', flexWrap: 'wrap', gap: 10, marginVertical: 10},
  statBox: {flexBasis: '47%', flexGrow: 1, backgroundColor: 'white', padding: 14, borderRadius: 12, borderWidth: 1, borderColor: '#e3e9df'},
  statLabel: {fontSize: 9, letterSpacing: 1, color: '#6c8271', marginBottom: 4},
  statNumber: {fontSize: 28, fontWeight: '800', color: '#193f31'},
  statSub: {fontSize: 11, color: '#88988c', marginTop: 2},
  smallActionBtn: {backgroundColor: '#edf3e9', padding: 10, borderRadius: 8, alignItems: 'center', marginVertical: 3},
  smallActionBtnActive: {backgroundColor: '#226b56'},
  smallActionIcon: {fontSize: 16, marginBottom: 2, color: '#226b56'},
  smallActionTitle: {fontSize: 12, fontWeight: '600', color: '#264a37'},
  tabToggle: {flexDirection: 'row', gap: 8, marginBottom: 12},
  toggleBtn: {flex: 1, paddingVertical: 9, alignItems: 'center', borderRadius: 6, backgroundColor: '#edf3e9'},
  toggleBtnActive: {backgroundColor: '#226b56'},
  toggleText: {fontSize: 11, fontWeight: '700', color: '#385e45'},
  toggleTextActive: {color: 'white'},
  recentItem: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 10, borderBottomWidth: 1, borderColor: '#f0f3ed'},
  recentText: {fontSize: 13, fontWeight: '600', color: '#264a37'},
  recentSub: {fontSize: 11, color: '#88988c', marginTop: 2},
  badgeRow: {flexDirection: 'row', marginVertical: 6},
  badgeText: {fontSize: 11, fontWeight: '700', paddingHorizontal: 8, paddingVertical: 4, borderRadius: 6},
  badgeNormal: {backgroundColor: '#edf3e9', color: '#226b56'},
  badgeHigh: {backgroundColor: '#fcece9', color: '#b24a40'},
  badgePending: {backgroundColor: '#fbf3e0', color: '#a07c31'},
  notice: {backgroundColor: '#eaf1dd', padding: 18, borderRadius: 12, marginVertical: 10},
  tipItem: {fontSize: 12, color: '#375940', lineHeight: 20, marginVertical: 2},
  coverageRow: {flexDirection: 'row', gap: 10, alignItems: 'flex-start', marginVertical: 8},
  checkIcon: {fontSize: 14, fontWeight: '800', color: '#226b56', marginTop: 2},
  coverageTitle: {fontSize: 13, fontWeight: '700', color: '#264a37'},
  mfaEnrollBox: {backgroundColor: '#f8faf6', padding: 14, borderRadius: 8, borderWidth: 1, borderColor: '#e1e8dc', marginVertical: 8},
  secretKeyText: {fontSize: 13, fontWeight: '800', color: '#226b56', letterSpacing: 1.5, textAlign: 'center', marginVertical: 10, backgroundColor: '#edf3e9', padding: 10, borderRadius: 6},
  messageBox: {backgroundColor: '#f5f7f1', padding: 12, borderRadius: 8, color: '#3a5840', lineHeight: 20, fontSize: 13, marginVertical: 8},
  evidence: {paddingVertical: 12, borderBottomWidth: 1, borderColor: '#e9ede5'},
  footer: {fontSize: 11, lineHeight: 18, color: '#82917e', textAlign: 'center', marginTop: 25},
});
