import { useRouter } from "next/router";
import { useState, useEffect } from "react";
import style from "../../pages/styles/LoginPage.module.scss";
import Axios from "axios";
import {useSelector} from "react-redux";

const MypageBody = () => {
  const route = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("")
  const username = useSelector((state) => state.userName);

  const handleMyInfo = (e) => {
    e.preventDefault();
    Axios.put("http://localhost:4000/editUser", {
      token: token,
      password: password,
      email: email
    })
    .then((res) => {
      console.log(res);
      alert('수정이 완료되었습니다')
      route.push('/')
    })
    .catch((err) => {console.log(err)})
  }

  useEffect(() => {
    setToken(localStorage.getItem('token'))
  }, [])

  return(
    <div className={style.LoginBodyContainer}>
    <div className={style.LoginContainer}>
      <p>{`${username}님 수정할 정보를 입력해 주세요 :)`}</p>
      <form>
        <input placeholder="Email" type="email" onChange={(e) => {
          e.preventDefault()
          setEmail(e.target.value)
        }} />
        <input placeholder="Password" type="password" onChange={(e) => {
          e.preventDefault()
          setPassword(e.target.value)
        }} />
        <button onClick={handleMyInfo}>정보 수정</button>
      </form>
    </div>
  </div>
  )
}

export default MypageBody;
