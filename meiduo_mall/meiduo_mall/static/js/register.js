//我们采用的是ES6的语法方式
//创建vue对象
let vm = new Vue({
    //第一步：通过ID选择器找到绑定的html内容
    el:'#app' ,
    //修改vue读取的语法
    delimiters:['[[',']]'],
    //数据对象
    data:{
    //    v-model
    username:'',
    password:'',
    mobile:'',
    allow:'',
    image_code_url:'',
    uuid:'',
    image_code:'',
    sms_code:'',
    sms_code_tip:'获取短信验证码',
    send_flag:false, //类比上厕所，send_flag就是锁，false表示门开，true表示门锁
    //    v-show 默认值为布尔类型false
    error_name:false,
    error_password:false,
    error_password2:false,
    error_mobile:false,
    error_allow:false,
    error_image_code:false,
    error_sms_code:false,

    //  error_message
     error_name_message:'' ,
     error_mobile_message:'',
    error_image_code_message:'',
    error_sms_code_message:'',
    },
    mounted(){//页面加载完会被调用的
        //生成图形验证码
        this.generate_image_code();
    },
    methods: {//定义和实现事件方法
        //生成图形验证码的方法,这是一个封装的思想，方便以后代码复用
        send_sms_code(){
            //避免恶意用户频繁点击获取短信验证码的标签
            if(this.send_flag==true){//先判断是否有人正在上厕所
                return; //有人正在上厕所，退回去
            }
            this.send_flag==true; //如果可以进入到厕所，立刻关门
            //校验数据：mobile,image_code
            //需要进行校验，因为之前都进行了校验，没校验之前的无法发送短信验证码
            this.check_mobile();
            this.check_image_code();
            if (this.error_mobile==true||this.error_image_code==true){
                this.send_flag=false;
                return;
            }
            let url='sms_codes/'+this.mobile+'/?image_code='+this.image_code+'&uuid='+this.uuid;
            axios.get(url,{
                responseType:'json'
            })
                .then(response=>{
                    if(response.data.code=='0'){
                        //展示倒计时60秒效果
                        // setInterval('回调函数','时间间隔(单位为毫秒)')
                        let num=60;
                        //t是倒计时器的编号
                        let t=setInterval(()=>{
                            if(num==1){
                                //倒计时即将结束
                                //停止回调函数的执行
                                clearInterval(t)
                                //还原sms_code_tip的提示文字
                                this.sms_code_tip='获取短信验证码';
                                this.generate_image_code();//重新生成图形验证码
                                this.send_flag=false;
                            }else{
                                //正在倒计时
                                num-=1;//num=num-1
                                this.sms_code_tip=num+'秒'
                            }

                        },1000)
                    }else{
                        //图形验证码失效
                    if(response.data.code=='4001'){
                        this.error_image_code_message=response.data.errmsg;
                        this.error_image_code=true
                    }
                    this.send_flag=false;

                    }
                })
                .catch(error=>{
                    console.log(error.response);
                    this.send_flag=false;
                })
        },

        generate_image_code(){
            this.uuid=generateUUID();
            this.image_code_url='/image_codes/'+this.uuid+'/';
        },
        //    校验用户名
        check_username() {
            let re = /^[a-zA-Z0-9_-]{5,20}$/;
            if (re.test(this.username)) {
                this.error_name = false;
            } else {
                this.error_name_message = '请输入5-20个字符的用户名';
                this.error_name = true;
            }
            //判断用户名是否重复注册
            //只有当用户输入的用户名满足条件才会去判断，url后面是请求头
            if(this.error_name == false){
                let url='/usernames/'+this.username+'/count/';
                axios.get(url, {
                    responseType:'json'
                })
                    .then((response)=>{
                        //data是响应体
                        if(response.data.count==1){
                            //用户名已经存在
                            this.error_name_message='用户名已存在'
                            this.error_name = true;
                        }else{
                            // 用户名不存在，可以进行
                            this.error_name = false;
                        }
                    })
                    .catch((error)=>{
                        console.log(error.response)
                    })

            }

        },
        //    校验密码
        check_password() {
            let re = /^[a-zA-Z0-9]{8,20}$/;
            if (re.test(this.password)) {
                this.error_password = false;
            } else {
                this.error_password = true;
            }

        },
        // 校验确认密码
        check_password2() {
            if (this.password != this.password2) {
                this.error_password = true;
            } else {
                this.error_password = false;
            }

        },

        // 校验手机号
        check_mobile() {
            let re = /^1[3-9]\d{9}$/;
            if (re.test(this.mobile)) {
                this.error_mobile = false;
            } else {
                this.error_mobile = true;
                this.error_name_message = '请输入正确的电话号码';

            }
            if (this.error_mobile == false) {
                let url = '/mobiles/' + this.mobile + '/count/';
                axios.get(url, {
                    responseType: 'json'
                })
                    .then((response) => {
                        if (response.data.count == 1) {
                            this.error_mobile_message = '电话号码已存在'
                            this.error_mobile = true;
                        } else {
                            this.error_mobile = false;
                        }
                    }).catch((error) => {
                    console.log(error.response)
                })
            }
        },
        //校验图形验证码
        check_image_code(){
            if(this.image_code.length!=4){
                this.error_image_code_message='请输入图形验证码';
                this.error_image_code=true;
            }else{
                this.error_image_code=false;
            }
        },
        // 校验短信验证码
        check_sms_code(){
            if(this.sms_code.length!=6){
                this.error_sms_code_message='请输入短信验证码';
                this.error_sms_code=true;
            }else{
                this.error_sms_code=false;
            }
        },
        // 校验是否勾选协议
        check_allow(){
            if (!this.allow) {
                this.error_allow = true;
            } else {
                this.error_allow = false;
            }
        },
        // 监听表单提交事件
        on_submit() {
            this.check_username();
            this.check_password();
            this.check_password2();
            this.check_mobile();
            this.check_allow();
            if (this.error_name == true || this.error_password == true || this.error_password2 == true
                || this.error_mobile == true || this.error_allow == true) {
                // 禁用表单的提交
                window.event.returnValue = false;
            }

        },
    }


});