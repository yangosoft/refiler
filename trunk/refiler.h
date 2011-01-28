int attach_child(pid_t pid, const char *pty, int old_fd);
void die(const char *msg, ...);
void debug(const char *msg, ...);
void error(const char *msg, ...);
