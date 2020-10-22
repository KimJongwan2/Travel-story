import 'reflect-metadata';
import * as express from 'express';
import * as bodyParser from 'body-parser';
import * as cors from 'cors';
import * as jwt from 'jsonwebtoken'
import * as crypto from 'crypto'
import * as cookieParser from 'cookie-parser'
import {
    createConnection,
    getRepository,
    getConnection,
    createQueryBuilder,
} from 'typeorm';
import { User, Content, Image, Tag } from './entity';
const secret = require('./config/jwt.json');
const password = require('./config/google.json');
const s3key = require('./config/s3.json');

const hash = (password) => {
    return crypto.createHmac('sha256', secret.secret)
        .update(password)
        .digest('hex')
}
createConnection()
    .then(async () => {
        class App {
            public app: express.Application;

            /**
             * @ class App
             * @ method bootstrap
             * @ static
             *
             */
            public static bootstrap(): App {
                return new App();
            }

            constructor() {
                this.app = express();
                this.app.use(
                    cors({
                        origin: '*',
                        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTION'],
                        credentials: true,
                    })
                );
                this.app.use(bodyParser.json());
                this.app.use(
                    bodyParser.urlencoded({
                        extended: false,
                    })
                );
                this.app.use(cookieParser(secret.secret))
                //배포시 경로 바꿔서 파비콘 적용하기(정적 파일제공 참고)
                // this.app.use(favicon(__dirname + '../images/favicon.ico'));

                //최신 글 받기
                this.app.get(
                    '/NewPost',
                    async (req: express.Request, res: express.Response) => {
                        const content = await getRepository(Content.Content)
                            .createQueryBuilder('content')
                            .orderBy('created_at', 'DESC')
                            .leftJoinAndSelect('content.images', 'image')
                            .leftJoinAndSelect('content.tags', 'tag')
                            .getMany()
                            .then((result) => res.status(200).send(result))
                            .catch((err) => res.sendStatus(404));
                    }
                );

                //제목 검색
                this.app.post(
                    '/serch/title',
                    async (req: express.Request, res: express.Response) => {
                        const content = await getRepository(User.User)
                            .createQueryBuilder('user')
                            .leftJoinAndSelect('user.contents', 'content')
                            .where('content.title like :title', {
                                title: `%${req.body.title}%`,
                            })
                            .leftJoinAndSelect('content.images', 'image')
                            .leftJoinAndSelect('content.tags', 'tag')
                            .getMany().then(result => res.status(200).send(result))
                            .catch((err) => res.sendStatus(404));
                    }
                );
                //태그 검색
                this.app.post(
                    '/serch/tag',
                    async (req: express.Request, res: express.Response) => {
                        const content = await getRepository(User.User)
                            .createQueryBuilder('user')
                            .leftJoinAndSelect('user.contents', 'content')
                            .leftJoinAndSelect('content.images', 'image')
                            .leftJoinAndSelect('content.tags', 'tag')
                            .where('tag.tagName like :tagName', {
                                tagName: `%${req.body.tagName}%`,
                            })
                            .getMany().then(result => res.status(200).send(result))
                            .catch((err) => res.sendStatus(404));
                    }
                );
                //게시글 추가
                this.app.post(
                    '/addPost',
                    async (req: express.Request, res: express.Response) => {
                        const user = await getRepository(User.User).findOne({
                            username: req.body.username,
                        });
                        //글 추가
                        const content = await getConnection()
                            .createQueryBuilder()
                            .insert()
                            .into(Content.Content)
                            .values([{ title: req.body.title, user }])
                            .execute()
                            .then((result) => {
                                //이미지 추가
                                const imageRepository = getRepository(
                                    Image.Image
                                );
                                const image = imageRepository.create();
                                image.imgName = req.body.imgName;
                                image.content = result.identifiers[0].id;
                                imageRepository.save(image);
                                //태그 추가
                                const tagRepository = getRepository(Tag.Tag);
                                const tag = tagRepository.create();
                                tag.tagName = req.body.tagName;
                                tag.content = result.identifiers[0].id;
                                tagRepository.save(tag);
                            }).then(result => res.sendStatus(201))
                            .catch((err) => res.sendStatus(404));
                    }
                );
                //게시글 수정
                this.app.put(
                    '/post',
                    async (req: express.Request, res: express.Response) => {
                        const user = await getRepository(User.User).find({
                            username: req.body.username,
                        });
                        const content = await getRepository(
                            Content.Content
                        ).findOne({
                            title: req.body.title,
                            created_at: req.body.created_at,
                        });
                        await getConnection()
                            .createQueryBuilder()
                            .update(Content.Content)
                            .set({ title: req.body.title })
                            .where(
                                `content.created_at = '${req.body.created_at}'`,
                                { user }
                            )
                            .execute();
                        await getConnection()
                            .createQueryBuilder()
                            .update(Image.Image)
                            .set({ imgName: req.body.imgName })
                            .where(`content.id = ${content.id}`)
                            .execute();
                        await getConnection()
                            .createQueryBuilder()
                            .update(Tag.Tag)
                            .set({ tagName: req.body.tagName })
                            .where(`content.id = ${content.id}`)
                            .execute()
                            .catch((err) => res.sendStatus(404));
                        return res.sendStatus(201);
                    }
                );

                //게시글 삭제  
                this.app.post(
                    '/postDelete',
                    async (req: express.Request, res: express.Response) => {
                        const user = await getRepository(User.User).find({
                            username: req.body.username,
                        });
                        const deleteContent = await getConnection()
                            .createQueryBuilder()
                            .delete()
                            .from(Content.Content)
                            .where(
                                `content.created_at = '${req.body.created_at}' and content.title = '${req.body.title}' `,
                                { user }
                            )
                            .execute()
                            .then((result) =>
                                res.sendStatus(200)
                            )
                            .catch((err) => {
                                console.log(err);
                                res.sendStatus(404);
                            });
                    }
                );

                //게시글 상세정보
                this.app.post(
                    '/post',
                    async (req: express.Request, res: express.Response) => {

                        const content = await getRepository(User.User)
                            .createQueryBuilder('user')
                            .leftJoinAndSelect('user.contents', 'content')
                            .where('content.id like :id', {
                                id: `%${req.body.id}%`,
                            })
                            .leftJoinAndSelect('content.images', 'image')
                            .leftJoinAndSelect('content.tags', 'tag')
                            .getOne()
                            .then(result => res.status(200).send(result))

                    }
                );

                // 회원가입(암호화)
                this.app.post(
                    '/signup',
                    async (req: express.Request, res: express.Response) => {
                        const { username, email, password } = req.body
                        //비밀번호 암호화
                        const hashPassword = hash(password)
                        const user = await getRepository(User.User).findOne({
                            email: req.body.email,
                        });
                        if (user) {
                            return res.sendStatus(404);
                        } else {
                            const addUser = await getRepository(
                                User.User
                            )
                                .create({ username, email, password: hashPassword })
                            const result = await getRepository(User.User)
                                .save(addUser).then(result => res.sendStatus(201))
                                .catch((err) => res.sendStatus(404));
                        }
                    }
                );
                //로그인 (일반 로그인 쿠키 7일 생성)
                this.app.post(
                    '/login',
                    async (req: express.Request, res: express.Response) => {
                        const { email, password } = req.body
                        const hashPassword = hash(password)
                        try {
                            const user = await getRepository(User.User).findOne(
                                {
                                    email: email,
                                    password: hashPassword
                                }
                            );
                            if (!user) {
                                return res.sendStatus(403)
                            }
                            if (user) {
                                const token = jwt.sign({ userId: user.email }, secret.secret, { expiresIn: '7d' })
                                return res.status(200).send({ user, token })
                            }
                        } catch (error) {
                            console.error(error);
                        }
                    }
                );
                //구글 로그인
                this.app.post('/googleLogin', async (req: express.Request, res: express.Response) => {
                    const { email, username } = req.body
                    const hashPassword = hash(email)
                    const user = await getRepository(User.User).findOne({
                        email
                    })
                    const token = jwt.sign({ userId: email }, secret.secret, { expiresIn: '7d' })
                    if (!user) {
                        const AddUser = getRepository(User.User)
                            .create({ username, email, password: hashPassword })
                        getRepository(User.User).save(AddUser)
                    }
                    const sendUser = await getRepository(User.User).find({
                        email
                    })
                    return res.status(200).send({ token, sendUser })
                })

                //비밀번호 찾기 
                this.app.put('/forgetPassword', async (req: express.Request, res: express.Response) => {
                    const nodemailer = require('nodemailer');
                    const smtpPool = require('nodemailer-smtp-pool');
                    const { email } = req.body
                    const newPassword = Math.random().toString(36).substr(2, 11)

                    const user = await getRepository(User.User).findOne({
                        email
                    })
                    if (user) {
                        createQueryBuilder()
                            .update(User.User)
                            .set({ password: hash(newPassword) })
                            .where("email = :email", { email })
                            .execute()
                        const transporter = nodemailer.createTransport(smtpPool({
                            service: "Gmail",
                            host: 'localhost',
                            tls: {
                                rejectUnauthorize: false
                            },
                            auth: {
                                user: 'turn3361@gmail.com',
                                pass: password.password
                            },
                            maxConnections: 5,
                            maxMessages: 10
                        }))
                        const mailOpt = {
                            from: 'turn3361@gmail.com',
                            to: email,
                            subject: 'Travel Story 임시 비밀번호 입니다.',
                            html: `<h2>Travel Story의 임시 비밀번호 입니다. ${newPassword}</h2>`
                        }
                        transporter.sendMail(mailOpt, function (err, res) {
                            if (err) {
                                console.error(err);
                            } else {
                                console.log('Message send :' + res);
                            }
                            // smtpTransport.close();
                        });
                        return res.sendStatus(201)
                    }
                    if (!user) {
                        return res.sendStatus(404)
                    }

                })

                //회원정보 수정

                this.app.put('/editUser', async (req: express.Request, res: express.Response) => {
                    const { token, email, password } = req.body
                    const user = await getRepository(User.User).findOne(
                        email
                    )

                    if (user) {
                        createQueryBuilder()
                            .update(User.User)
                            .set({ password: hash(password) })
                            .where("email = :email", { email })
                            .execute()
                        return res.sendStatus(201)
                    }
                    if (!user) {
                        return res.sendStatus(404)
                    }
                })


                //채팅 구현
                const http = require('http');
                const socketIO = require('socket.io')
                const port = 5000;
                const server = http.createServer(this.app)
                const io = socketIO(server);
                io.on('connection', socket => {
                    socket.on('send message', (item) => {
                        const msg = item.name + ' : ' + item.message;
                        console.log(msg);
                        io.emit('receive message', { name: item.name, message: item.message });
                    });
                    socket.on('disconnect', function () {
                        console.log('user disconnected: ', socket.id);
                    });
                });

                //내 글 가져오기
                this.app.post(
                    '/myPost',
                    async (req: express.Request, res: express.Response) => {
                        const { username } = req.body
                        const content = await getRepository(Content.Content)
                            .createQueryBuilder('content')
                            .leftJoinAndSelect('content.user', 'user')
                            .where('user.username = :username',{ username })
                            .orderBy('created_at','DESC')
                            .getMany()
                            .then((result) => res.status(200).send(result))
                            .catch((err) => console.log(err));
                    }
                );

                //사진 업로드 구현
                const aws = require('aws-sdk');
                const multer = require('multer');
                const multerS3 = require('multer-s3');
                const moment = require('moment');
                
                const s3 = new aws.S3({
                  accessKeyId: s3key.accessKeyId, // 생성한 s3의 accesskey 
                  secretAccessKey: s3key.secretAccessKey, // 생성한 s3의 secret key 
                  region: 'ap-northeast-2'  // 지역설정 
                })
                
                const storage = multerS3({
                  s3: s3,
                  bucket: 'image-test-file', // s3 생성시 버킷명
                  acl: 'public-read',   // 업로드 된 데이터를 URL로 읽을 때 설정하는 값입니다. 업로드만 한다면 필요없습니다.
                  metadata: function (req, file, cb) {
                    cb(null, {fieldName: file.fieldname}); // 파일 메타정보를 저장합니다.
                  },
                  key: function (req, file, cb) {
                    cb(null, moment().format('YYYYMMDDHHmmss') + "_" + file.originalname) // key... 저장될 파일명과 같이 해봅니다.
                  }
                })
                
                const upload = multer({ storage: storage }).single("img");

                this.app.post('/upload', async (req: express.Request, res: express.Response, next:express.NextFunction) => {
                    upload(req, res, function(err) {
                      if (err instanceof multer.MulterError) {
                        return next(err);
                      } else if (err) {
                        return next(err);
                      }
                      return res.status(200);
                    });
                  });


                server.listen(port, () => console.log(`Listening on port ${port}`))


            }
        }

        const port: number = Number(process.env.PORT) || 4000;
        const app: express.Application = new App().app;

        app.listen(port, () =>
            console.log(`Express server listening at ${port}`)
        ).on('error', (err) => console.error(err));
    })
    .catch((error) => console.log(error));
