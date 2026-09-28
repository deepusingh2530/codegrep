pid_t p = fork();
if (p == 0) execl("/bin/ls", "ls", NULL);
