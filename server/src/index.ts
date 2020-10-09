import 'reflect-metadata';
import * as express from 'express';
import * as bodyParser from 'body-parser';
import * as cors from 'cors';
import { createConnection } from 'typeorm';
import { User, Content, Image, Tag } from './entity';

createConnection()
    .then(async (connection) => {
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
                        methods: ['GET', 'POST', 'PUT', 'DELETE'],
                        credentials: true,
                    })
                );
                this.app.use(bodyParser.json());
                this.app.use(
                    bodyParser.urlencoded({
                        extended: false,
                    })
                );

                //배포시 경로 바꿔서 파비콘 적용하기(정적 파일제공 참고)
                // this.app.use(favicon(__dirname + '../images/favicon.ico'));

                this.app.get(
                    '/',
                    async (
                        req: express.Request,
                        res: express.Response,
                        next: express.NextFunction
                    ) => {
                        const userRepository = connection.getRepository(
                            User.User
                        );
                        const users = await userRepository.find();
                        res.json(users);
                    }
                );
            }
        }

        const port: number = Number(process.env.PORT) || 4000;
        const app: express.Application = new App().app;

        app.listen(port, () =>
            console.log(`Express server listening at ${port}`)
        ).on('error', (err) => console.error(err));
    })
    .catch((error) => console.log(error));