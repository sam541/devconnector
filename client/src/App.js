import React, { Fragment, useEffect } from "react";
import { BrowserRouter as Router, Route, Switch } from "react-router-dom";
import Navbar from "./components/layout/Navbar";
import Landing from "./components/layout/Landing";
import Login from "./components/auth/Login";
import Register from "./components/auth/Register";
import Alert from "./components/layout/Alert";
import Dashboard from "./components/dashboard/Dashboard";
import CreateProfile from "./components/profile-forms/CreateProfile";
import EditProfile from "./components/profile-forms/EditProfile";
import PrivateRoute from "./components/routing/PrivateRoute";
//Redux
import { Provider } from "react-redux";
import store from "./store";
import { loadUser } from "./actions/auth";
import setAuthToken from "./utils/setAuthToken";

import "./App.css";

if (localStorage.token) {
  setAuthToken(localStorage.token);
}

const App = () => {
  useEffect(() => {
    store.dispatch(loadUser());
  }, []);

  return (
    <div className='App'>
      <Provider store={store}>
        <Router>
          <Fragment>
            <Navbar></Navbar>
            <Route exact path='/' component={Landing}></Route>
            <section className='container'>
              <Alert></Alert>
              <Switch>
                <Route exact path='/register' component={Register}></Route>
                <Route exact path='/login' component={Login}></Route>
                <PrivateRoute
                  exact
                  path='/dashboard'
                  component={Dashboard}
                ></PrivateRoute>
                <PrivateRoute
                  exact
                  path='/create-profile'
                  component={CreateProfile}
                ></PrivateRoute>
                <PrivateRoute
                  exact
                  path='/edit-profile'
                  component={EditProfile}
                ></PrivateRoute>
              </Switch>
            </section>
          </Fragment>
        </Router>
      </Provider>
    </div>
  );
};

export default App;
