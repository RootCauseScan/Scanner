package audit.docker

# Detect containers running as root
deny[msg] if {
    input.file_type == "dockerfile"
    node := input.nodes[_]
    node.path == "USER"
    contains(node.value, "root")
    msg := "Container runs as root user - use a non-root user for security"
}

# Detect use of 'latest' tag in FROM
deny[msg] if {
    input.file_type == "dockerfile"
    node := input.nodes[_]
    node.path == "FROM"
    contains(node.value, ":latest")
    msg := "Using 'latest' tag is not recommended - specify exact version"
}

# Detect use of ADD instead of COPY
deny[msg] if {
    input.file_type == "dockerfile"
    node := input.nodes[_]
    node.path == "ADD"
    msg := "Use COPY instead of ADD for local files"
}

# Detect privileged containers
deny[msg] if {
    input.file_type == "dockerfile"
    node := input.nodes[_]
    node.path == "RUN"
    contains(node.value, "sudo")
    msg := "Avoid using sudo in containers - not needed and security risk"
}