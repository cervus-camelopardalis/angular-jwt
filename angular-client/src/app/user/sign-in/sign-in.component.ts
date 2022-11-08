import { Component, OnInit } from '@angular/core';

import { FormGroup } from '@angular/forms';
import { FormControl } from '@angular/forms';
import { Validators } from '@angular/forms';

@Component({
  selector: 'app-sign-in',
  templateUrl: './sign-in.component.html',
  styleUrls: ['./sign-in.component.scss']
})
export class SignInComponent implements OnInit {

  hide = true;

  formSignIn = new FormGroup({
    "email": new FormControl("", Validators.required),
    "password": new FormControl("", Validators.required),
  });
    
  onSubmitSignIn() {
    console.log("Sign in: Reactive form submitted ✓");
    console.log(this.formSignIn.value);
  }

  constructor() { }

  ngOnInit(): void {
  }

}
