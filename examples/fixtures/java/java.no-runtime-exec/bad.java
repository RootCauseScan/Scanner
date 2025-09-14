class Bad {
    public void run() throws Exception {
        Runtime.getRuntime().exec("ls");
    }
}
