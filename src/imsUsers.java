class imsUsers{
    public String sipUsername;
    public String sipnonce;
    public String passwd;
    public int used=0;
    public  imsUsers(String sipUsername, String sipnonce,String passwd){
        this.sipUsername=sipUsername;
        this.sipnonce=sipnonce;
        this.passwd=passwd;
        this.used=0;
    }
}